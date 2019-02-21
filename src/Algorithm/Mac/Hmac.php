<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Cose\Algorithm\Mac;

use Assert\Assertion;
use Cose\Key\Key;

abstract class Hmac implements Mac
{
    public function hash($data, Key $key)
    {
        $this->checKey($key);
        $signature = hash_hmac($this->getHashAlgorithm(), $data, $key->get(-1), true);

        return mb_substr($signature, 0, $this->getSignatureLength() / 8, '8bit');
    }

    public function verify($data, Key $key, $signature)
    {
        return hash_equals($this->hash($data, $key), $signature);
    }

    private function checKey(Key $key)
    {
        Assertion::eq($key->type(), 4, 'Invalid key. Must be of type symmetric');
        Assertion::true($key->has(-1), 'Invalid key. The value of the key is missing');
    }

    abstract protected function getHashAlgorithm();

    abstract protected function getSignatureLength();
}
