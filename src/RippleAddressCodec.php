<?php
/**
 * User: Lessmore92
 * Date: 1/6/2021
 * Time: 1:49 AM
 */

namespace Lessmore92\RippleAddressCodec;

use Exception;
use Lessmore92\Buffer\Buffer;

define('ACCOUNT_ID', 0);                     // Account address (20 bytes)
define('ACCOUNT_PUBLIC_KEY', 0x23);          // Account address (20 bytes)
define('FAMILY_SEED', 0x21);                 // 33; Seed value (for secret keys) (16 bytes)
define('ED25519_SEED', [0x01, 0xE1, 0x4B]);  // [1, 225, 75])
define('NODE_PUBLIC', 0x1C);                 // 28; Validation public key (33 bytes)
define('MAX_32_BIT_UNSIGNED_INT', 4294967295);
define('PREFIX_BYTES', [
    'MAIN' => [0x05, 0x44],
    'TEST' => [0x04, 0x93],
]);

class RippleAddressCodec
{
    private $alphabet = 'rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz';
    private $codec;

    public function __construct()
    {
        $this->codec = new CodecWithXrpAlphabet($this->alphabet);
    }

    public function encodeSeed(Buffer $entropy, $type): string
    {
        if ($entropy->getSize() !== 16)
        {
            throw new Exception('entropy must have length 16');
        }

        $options = [
            'expectedLength' => 16,
            // for secp256k1, use `FAMILY_SEED`
            'versions'       => $type === 'ed25519' ? ED25519_SEED : [FAMILY_SEED],
        ];

        return $this->codec->encode($entropy, $options);
    }

    public function decodeSeed(string $seed, $options = []): array
    {
        $options = array_replace([
            'versionTypes'   => ['ed25519', 'secp256k1'],
            "versions"       => [ED25519_SEED, FAMILY_SEED],
            "expectedLength" => 16,
        ], $options);

        return $this->codec->decode($seed, $options);
    }

    public function encodeAccountID(Buffer $bytes): string
    {
        $options = ['versions' => [ACCOUNT_ID], 'expectedLength' => 20];
        return $this->codec->encode($bytes, $options);
    }

    public function decodeNodePublic(string $base58string): Buffer
    {
        $options = ['versions' => [NODE_PUBLIC], 'expectedLength' => 33];
        return $this->codec->decode($base58string, $options)['bytes'];
    }

    public function encodeNodePublic(Buffer $bytes): string
    {
        $options = ['versions' => [NODE_PUBLIC], 'expectedLength' => 33];
        return $this->codec->encode($bytes, $options);
    }

    public function encodeAccountPublic(Buffer $bytes): string
    {
        $options = ['versions' => [ACCOUNT_PUBLIC_KEY], 'expectedLength' => 33];
        return $this->codec->encode($bytes, $options);
    }

    public function decodeAccountPublic(string $base58string): Buffer
    {
        $options = ['versions' => [ACCOUNT_PUBLIC_KEY], 'expectedLength' => 33];
        return $this->codec->decode($base58string, $options)['bytes'];
    }

    public function isValidClassicAddress(string $address): bool
    {
        try
        {
            $this->decodeAccountID($address);
        }
        catch (Exception $e)
        {
            return false;
        }
        return true;
    }

    public function decodeAccountID(string $accountId): Buffer
    {
        $options = ['versions' => [ACCOUNT_ID], 'expectedLength' => 20];
        return $this->codec->decode($accountId, $options)['bytes'];
    }

    public function classicAddressToXAddress(string $classicAddress, $tag, bool $test = false)
    {
        $accountBuffer = $this->decodeAccountID($classicAddress);
        return $this->encodeXAddress($accountBuffer, $tag, $test);
    }

    public function encodeXAddress(Buffer $accountId, $tag, bool $test = false): string
    {
        $flag = ($tag === false ? 0 : $tag <= MAX_32_BIT_UNSIGNED_INT) ? 1 : 2;
        if ($flag === 2)
        {
            throw new Exception('Invalid tag');
        }
        if ($tag === false)
        {
            $tag = 0;
        }

        $bytes = array_merge($test ? PREFIX_BYTES['TEST'] : PREFIX_BYTES['MAIN']);
        $bytes = array_merge($bytes, $accountId->getDecimal());
        $bytes = array_merge($bytes, [
            $flag,
            $tag & 0xff,
            ($tag >> 8) & 0xff,
            ($tag >> 16) & 0xff,
            ($tag >> 24) & 0xff,
            0, 0, 0, 0
        ]);

        $hex = array_map(function ($item) {
            return sprintf('%02X', $item);
        }, $bytes);

        return $this->codec->encodeChecked(Buffer::hex(join($hex)));
    }

    public function xAddressToClassicAddress(string $xAddress)
    {
        list($accountId, $tag, $test) = array_values($this->decodeXAddress($xAddress));
        $classicAddress = $this->encodeAccountID($accountId);
        return [
            'classicAddress' => $classicAddress,
            'tag'            => $tag,
            'test'           => $test,
        ];
    }

    public function decodeXAddress(string $xAddress)
    {
        $decoded   = $this->codec->decodeCheck($xAddress);
        $test      = $this->isBufferForTestAddress($decoded);
        $accountId = $decoded->slice(2, 20);
        $tag       = $this->tagFromBuffer($decoded);
        return [
            'accountId' => $accountId,
            'tag'       => $tag,
            'test'      => $test,
        ];
    }

    public function isBufferForTestAddress(Buffer $buffer): bool
    {
        $decodedPrefix = $buffer->slice(0, 2)
                                ->getDecimal()
        ;
        if (PREFIX_BYTES['MAIN'] === $decodedPrefix)
        {
            return false;
        }
        else if (PREFIX_BYTES['TEST'] === $decodedPrefix)
        {
            return true;
        }
        throw new Exception('Invalid X-address: bad prefix');
    }

    private function tagFromBuffer(Buffer $buffer)
    {
        $buf  = $buffer->getDecimal();
        $flag = $buf[22];
        if ($flag >= 2)
        {
            throw new Exception('Unsupported X-address');
        }

        if ($flag === 1)
        {
            // Little-endian to big-endian
            return $buf[23] + $buf[24] * 0x100 + $buf[25] * 0x10000 + $buf[26] * 0x1000000;
        }

        if ($flag === 0)
        {
            throw new Exception('flag must be zero to indicate no tag');
        }

        if ('0000000000000000' !== $buffer->slice(23, 23 + 8)
                                          ->getHex())
        {
            throw new Exception('remaining bytes must be zero');
        }
        return false;
    }

    public function isValidXAddress(string $xAddress)
    {
        try
        {
            $this->decodeXAddress($xAddress);
        }
        catch (Exception $e)
        {
            return false;
        }
        return true;
    }
}
