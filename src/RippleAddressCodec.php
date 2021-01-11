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
}
