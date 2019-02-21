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

class Key
{
    const TYPE = 1;
    const KID = 2;
    const ALG = 3;
    const KEY_OPS = 4;
    const BASE_IV = 5;

    /**
     * @var array
     */
    private $data;

    public function __construct(array $data)
    {
        Assertion::keyExists($data, self::TYPE, 'Invalid key: the type is not defined');
        $this->data = $data;
    }

    public static function createFromData(array $data): self
    {
        Assertion::keyExists($data, self::TYPE, 'Invalid key: the type is not defined');
        switch ($data[self::TYPE]) {
            case 1:
                return new OkpKey($data);
            case 2:
                return new Ec2Key($data);
            case 3:
                return new RsaKey($data);
            case 4:
                return new SymmetricKey($data);
            default:
                return new self($data);
        }
    }

    /**
     * @return int|string
     */
    public function type()
    {
        return $this->data[self::TYPE];
    }

    public function alg()
    {
        return (int) $this->get(self::ALG);
    }

    public function getData(): array
    {
        return $this->data;
    }

    public function has($key)
    {
        return \array_key_exists($key, $this->data);
    }

    /**
     * @return mixed
     */
    public function get($key)
    {
        Assertion::keyExists($this->data, $key, \Safe\sprintf('The key has no data at index %d', $key));

        return $this->data[$key];
    }
}
