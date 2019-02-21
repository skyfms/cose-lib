<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Cose\Algorithm\Signature\ECDSA;

use Cose\Algorithms;

final class ES512 extends ECDSA
{
    public static function identifier()
    {
        return Algorithms::COSE_ALGORITHM_ES512;
    }

    protected function getHashAlgorithm()
    {
        return OPENSSL_ALGO_SHA512;
    }

    protected function getCurve()
    {
        return 3;
    }
}
