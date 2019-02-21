<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Cose\Key;

use Assert\Assertion;
use FG\ASN1\Universal\BitString;
use FG\ASN1\Universal\Integer;
use FG\ASN1\Universal\NullObject;
use FG\ASN1\Universal\ObjectIdentifier;
use FG\ASN1\Universal\Sequence;

class RsaKey extends Key
{
    const DATA_N = -1;
    const DATA_E = -2;
    const DATA_D = -3;
    const DATA_P = -4;
    const DATA_Q = -5;
    const DATA_DP = -6;
    const DATA_DQ = -7;
    const DATA_QI = -8;
    const DATA_OTHER = -9;
    const DATA_RI = -10;
    const DATA_DI = -11;
    const DATA_TI = -12;

    public function __construct(array $data)
    {
        parent::__construct($data);
        Assertion::eq($data[self::TYPE], 3, 'Invalid RSA key. The key type does not correspond to a RSA key');
        Assertion::keyExists($data, self::DATA_N, 'Invalid RSA key. The modulus is missing');
        Assertion::keyExists($data, self::DATA_E, 'Invalid RSA key. The exponent is missing');
    }

    public function n()
    {
        return $this->get(self::DATA_N);
    }

    public function e()
    {
        return $this->get(self::DATA_E);
    }

    public function d()
    {
        Assertion::true($this->isPrivate(), 'The key is not private.');

        return $this->get(self::DATA_D);
    }

    public function p()
    {
        Assertion::true($this->isPrivate(), 'The key is not private.');

        return $this->get(self::DATA_P);
    }

    public function q()
    {
        Assertion::true($this->isPrivate(), 'The key is not private.');

        return $this->get(self::DATA_Q);
    }

    public function dP()
    {
        Assertion::true($this->isPrivate(), 'The key is not private.');

        return $this->get(self::DATA_DP);
    }

    public function dQ()
    {
        Assertion::true($this->isPrivate(), 'The key is not private.');

        return $this->get(self::DATA_DQ);
    }

    public function QInv()
    {
        Assertion::true($this->isPrivate(), 'The key is not private.');

        return $this->get(self::DATA_QI);
    }

    public function other(): array
    {
        Assertion::true($this->isPrivate(), 'The key is not private.');

        return $this->get(self::DATA_OTHER);
    }

    public function rI()
    {
        Assertion::true($this->isPrivate(), 'The key is not private.');

        return $this->get(self::DATA_RI);
    }

    public function dI()
    {
        Assertion::true($this->isPrivate(), 'The key is not private.');

        return $this->get(self::DATA_DI);
    }

    public function tI()
    {
        Assertion::true($this->isPrivate(), 'The key is not private.');

        return $this->get(self::DATA_TI);
    }

    public function hasPrimes()
    {
        return $this->has(self::DATA_P) && $this->has(self::DATA_Q);
    }

    public function primes(): array
    {
        return [
            $this->p(),
            $this->q(),
        ];
    }

    public function hasExponents()
    {
        return $this->has(self::DATA_DP) && $this->has(self::DATA_DQ);
    }

    public function exponents(): array
    {
        return [
            $this->dP(),
            $this->dQ(),
        ];
    }

    public function hasCoefficient()
    {
        return $this->has(self::DATA_QI);
    }

    public function isPublic()
    {
        return !$this->isPrivate();
    }

    public function isPrivate()
    {
        return \array_key_exists(self::DATA_D, $this->getData());
    }

    public function asPem()
    {
        Assertion::false($this->isPrivate(), 'Unsupported for private keys.');
        $bitSring = new Sequence(
            new Integer($this->fromBase64ToInteger($this->n())),
            new Integer($this->fromBase64ToInteger($this->e()))
        );

        $der = new Sequence(
            new Sequence(
                new ObjectIdentifier('1.2.840.113549.1.1.1'),
                new NullObject()
            ),
            new BitString(\bin2hex($bitSring->getBinary()))
        );

        return $this->pem('PUBLIC KEY', $der->getBinary());
    }

    private function fromBase64ToInteger($value)
    {
        return gmp_strval(gmp_init(current(unpack('H*', $value)), 16), 10);
    }

    private function pem($type, $der)
    {
        return \Safe\sprintf("-----BEGIN %s-----\n", mb_strtoupper($type)).
            chunk_split(base64_encode($der), 64, "\n").
            \Safe\sprintf("-----END %s-----\n", mb_strtoupper($type));
    }
}
