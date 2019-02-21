<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Cose\Algorithm\Signature\RSA;

use Assert\Assertion;
use Cose\Algorithm\Signature\Signature;
use Cose\Key\Key;
use Cose\Key\RsaKey;

abstract class RSA implements Signature
{
    public function sign($data, Key $key)
    {
        $key = $this->handleKey($key);
        Assertion::true($key->isPrivate(), 'The key is not private');

        \Safe\openssl_sign($data, $signature, $key->asPem(), $this->getHashAlgorithm());

        return $signature;
    }

    public function verify($data, Key $key, $signature)
    {
        $key = $this->handleKey($key);

        return 1 === openssl_verify($data, $signature, $key->asPem(), $this->getHashAlgorithm());
    }

    private function handleKey(Key $key): RsaKey
    {
        return new RsaKey($key->getData());
    }

    abstract protected function getHashAlgorithm();
}
