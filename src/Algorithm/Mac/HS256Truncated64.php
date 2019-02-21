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

use Cose\Algorithms;

final class HS256Truncated64 extends Hmac
{
    public static function identifier()
    {
        return Algorithms::COSE_ALGORITHM_HS256_64;
    }

    protected function getHashAlgorithm()
    {
        return 'sha256';
    }

    protected function getSignatureLength()
    {
        return 64;
    }
}
