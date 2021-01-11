<?php
/**
 * User: Lessmore92
 * Date: 1/6/2021
 * Time: 1:49 AM
 */

namespace Lessmore92\RippleAddressCodec;

use Exception;
use Lessmore92\BaseX\BaseX;
use Lessmore92\Buffer\Buffer;

class CodecWithXrpAlphabet
{
    private $alphabet;
    private $codec;
    private $base;

    public function __construct($alphabet)
    {
        $this->alphabet = $alphabet;
        $this->codec    = new BaseX($alphabet);
        $this->base     = sizeof(str_split($this->alphabet));
    }

    public function encode(Buffer $bytes, array $options): string
    {
        return $this->encodeVersioned($bytes, $options['versions'], $options['expectedLength']);
    }

    public function encodeVersioned(Buffer $bytes, $versions, $expectedLength): string
    {
        if ($bytes->getSize() !== $expectedLength)
        {
            throw new Exception('unexpected_payload_length: bytes.length does not match expectedLength. Ensure that the bytes are a Buffer.');
        }

        for ($i = count($versions) - 1; $i >= 0; $i--)
        {
            $bytes->prepend(sprintf('%02X', $versions[$i]));
        }

        return $this->encodeChecked($bytes);
    }

    public function encodeChecked(Buffer $buffer): string
    {
        $check = unpack('C*', substr(hash('sha256', hash('sha256', $buffer->getBinary(), true), true), 0, 4));
        foreach ($check as $item)
        {
            $buffer->append(sprintf('%02X', $item));
        }

        return $this->encodeRaw($buffer);
    }

    public function encodeRaw(Buffer $bytes): string
    {
        return $this->codec->encode($bytes);
    }

    public function decode(string $base58String, array $options = []): array
    {
        $withoutSum = $this->decodeCheck($base58String);

        $defaultOptions['versionTypes']   = ['ed25519', 'secp256k1'];
        $defaultOptions['versions']       = [[1, 225, 75], 33];
        $defaultOptions['expectedLength'] = 16;
        $options                          = array_replace($defaultOptions, $options);

        $versions = $options['versions'];
        $types    = $options['versionTypes'];

        if (sizeof($versions) > 1 && !$options['expectedLength'])
        {
            throw new Exception('expectedLength is required because there are >= 2 possible versions');
        }

        $versionLengthGuess = is_numeric($versions[0]) ? 1 : sizeof($versions[0]);
        $payloadLength      = $options['expectedLength'] ?: $withoutSum->getSize() - $versionLengthGuess;

        $versionBytes = $withoutSum->slice(0, (-1 * $payloadLength))
                                   ->getDecimal()
        ;
        $payload      = $withoutSum->slice((-1 * $payloadLength));

        for ($i = 0; $i < sizeof($versions); $i++)
        {
            $version = is_array($versions[$i]) ? $versions[$i] : [$versions[$i]];
            if ($version === $versionBytes)
            {
                return [
                    'version' => $version,
                    'bytes'   => $payload,
                    'type'    => $types ? $types[$i] : null,
                ];
            }
        }
    }

    public function decodeCheck(string $base58string): Buffer
    {
        $buffer = $this->decodeRaw($base58string);
        if ($buffer->getSize() < 5)
        {
            throw new Exception('invalid_input_size: decoded data must have length >= 5');
        }

        if (!$this->verifyCheckSum($buffer))
        {
            throw new Exception('checksum_invalid');
        }

        return $buffer->slice(0, -4);
    }

    public function decodeRaw(string $seed): Buffer
    {
        return $this->codec->decode($seed);
    }

    public function verifyCheckSum(Buffer $bytes): bool
    {
        $computed = substr(hash('sha256', hash('sha256', substr($bytes->getBinary(), 0, -4), true), true), 0, 4);
        $checksum = substr($bytes->getBinary(), -4);
        return $computed === $checksum;
    }
}
