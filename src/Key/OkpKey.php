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

class OkpKey extends Key
{
    const CURVE_X25519 = 4;
    const CURVE_X448 = 5;
    const CURVE_ED25519 = 6;
    const CURVE_ED448 = 7;

    const SUPPORTED_CURVES = [
        self::CURVE_X25519,
        self::CURVE_X448,
        self::CURVE_ED25519,
        self::CURVE_ED448,
    ];

    const DATA_CURVE = -1;
    const DATA_X = -2;
    const DATA_D = -4;

    public function __construct(array $data)
    {
        parent::__construct($data);
        Assertion::eq($data[self::TYPE], 1, 'Invalid OKP key. The key type does not correspond to an OKP key');
        Assertion::keyExists($data, self::DATA_CURVE, 'Invalid EC2 key. The curve is missing');
        Assertion::keyExists($data, self::DATA_X, 'Invalid OKP key. The x coordinate is missing');
        Assertion::inArray((int) $data[self::DATA_CURVE], self::SUPPORTED_CURVES, 'The curve is not supported');
    }

    public function x()
    {
        return $this->get(self::DATA_X);
    }

    public function isPrivate()
    {
        return \array_key_exists(self::DATA_D, $this->getData());
    }

    public function d()
    {
        Assertion::true($this->isPrivate(), 'The key is not private');

        return $this->get(self::DATA_D);
    }

    public function curve()
    {
        return (int) $this->get(self::DATA_CURVE);
    }
}
