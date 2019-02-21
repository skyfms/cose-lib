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

use Cose\Algorithm\Algorithm;
use Cose\Key\Key;

interface Mac extends Algorithm
{
    public function hash($data, Key $key);

    public function verify($data, Key $key, $signature);
}
