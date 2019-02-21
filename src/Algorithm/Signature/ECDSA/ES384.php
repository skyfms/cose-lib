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

final class ES384 extends ECDSA
{
    public static function identifier()
    {
        return Algorithms::COSE_ALGORITHM_ES384;
    }

    protected function getHashAlgorithm()
    {
        return OPENSSL_ALGO_SHA384;
    }

    protected function getCurve()
    {
        return 2;
    }
}
