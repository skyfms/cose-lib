<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Cose;

use Assert\Assertion;
use Cose\Algorithm\Algorithm;
use Cose\Algorithm\Mac;
use Cose\Algorithm\Signature\ECDSA;
use Cose\Algorithm\Signature\EdDSA;
use Cose\Algorithm\Signature\RSA;

/**
 * @see https://www.iana.org/assignments/cose/cose.xhtml#algorithms
 */
abstract class Algorithms
{
    const COSE_ALGORITHM_AES_CCM_64_128_256 = 33;
    const COSE_ALGORITHM_AES_CCM_64_128_128 = 32;
    const COSE_ALGORITHM_AES_CCM_16_128_256 = 31;
    const COSE_ALGORITHM_AES_CCM_16_128_128 = 30;
    const COSE_ALGORITHM_AES_MAC_256_128 = 26;
    const COSE_ALGORITHM_AES_MAC_128_128 = 25;
    const COSE_ALGORITHM_CHACHA20_POLY1305 = 24;
    const COSE_ALGORITHM_AES_MAC_256_64 = 15;
    const COSE_ALGORITHM_AES_MAC_128_64 = 14;
    const COSE_ALGORITHM_AES_CCM_64_64_256 = 13;
    const COSE_ALGORITHM_AES_CCM_64_64_128 = 12;
    const COSE_ALGORITHM_AES_CCM_16_64_256 = 11;
    const COSE_ALGORITHM_AES_CCM_16_64_128 = 10;
    const COSE_ALGORITHM_HS512 = 7;
    const COSE_ALGORITHM_HS384 = 6;
    const COSE_ALGORITHM_HS256 = 5;
    const COSE_ALGORITHM_HS256_64 = 4;
    const COSE_ALGORITHM_A256GCM = 3;
    const COSE_ALGORITHM_A192GCM = 2;
    const COSE_ALGORITHM_A128GCM = 1;
    const COSE_ALGORITHM_A128KW = -3;
    const COSE_ALGORITHM_A192KW = -4;
    const COSE_ALGORITHM_A256KW = -5;
    const COSE_ALGORITHM_DIRECT = -6;
    const COSE_ALGORITHM_ES256 = -7;
    const COSE_ALGORITHM_EdDSA = -8;
    const COSE_ALGORITHM_DIRECT_HKDF_SHA_256 = -10;
    const COSE_ALGORITHM_DIRECT_HKDF_SHA_512 = -11;
    const COSE_ALGORITHM_DIRECT_HKDF_AES_128 = -12;
    const COSE_ALGORITHM_DIRECT_HKDF_AES_256 = -13;
    const COSE_ALGORITHM_ECDH_ES_HKDF_256 = -25;
    const COSE_ALGORITHM_ECDH_ES_HKDF_512 = -26;
    const COSE_ALGORITHM_ECDH_SS_HKDF_256 = -27;
    const COSE_ALGORITHM_ECDH_SS_HKDF_512 = -28;
    const COSE_ALGORITHM_ECDH_ES_A128KW = -29;
    const COSE_ALGORITHM_ECDH_ES_A192KW = -30;
    const COSE_ALGORITHM_ECDH_ES_A256KW = -31;
    const COSE_ALGORITHM_ECDH_SS_A128KW = -32;
    const COSE_ALGORITHM_ECDH_SS_A192KW = -33;
    const COSE_ALGORITHM_ECDH_SS_A256KW = -34;
    const COSE_ALGORITHM_ES384 = -35;
    const COSE_ALGORITHM_ES512 = -36;
    const COSE_ALGORITHM_PS256 = -37;
    const COSE_ALGORITHM_PS384 = -38;
    const COSE_ALGORITHM_PS512 = -39;
    const COSE_ALGORITHM_RSAES_OAEP = -40;
    const COSE_ALGORITHM_RSAES_OAEP_256 = -41;
    const COSE_ALGORITHM_RSAES_OAEP_512 = -42;
    const COSE_ALGORITHM_RS256 = -257;
    const COSE_ALGORITHM_RS384 = -258;
    const COSE_ALGORITHM_RS512 = -259;
    const COSE_ALGORITHM_RS1 = -65535;

    public static $COSE_ALGORITHM_MAP = [
        self::COSE_ALGORITHM_ES256 => OPENSSL_ALGO_SHA256,
        self::COSE_ALGORITHM_ES384 => OPENSSL_ALGO_SHA384,
        self::COSE_ALGORITHM_ES512 => OPENSSL_ALGO_SHA512,
        self::COSE_ALGORITHM_RS256 => OPENSSL_ALGO_SHA256,
        self::COSE_ALGORITHM_RS384 => OPENSSL_ALGO_SHA384,
        self::COSE_ALGORITHM_RS512 => OPENSSL_ALGO_SHA512,
        self::COSE_ALGORITHM_RS1 => OPENSSL_ALGO_SHA1,
    ];

    public static $COSE_HASH_MAP = [
        self::COSE_ALGORITHM_ES256 => 'sha256',
        self::COSE_ALGORITHM_ES384 => 'sha384',
        self::COSE_ALGORITHM_ES512 => 'sha512',
        self::COSE_ALGORITHM_RS256 => 'sha256',
        self::COSE_ALGORITHM_RS384 => 'sha384',
        self::COSE_ALGORITHM_RS512 => 'sha512',
        self::COSE_ALGORITHM_RS1 => 'sha1',
    ];

    public static function getOpensslAlgorithmFor($algorithmIdentifier)
    {
        Assertion::keyExists(self::$COSE_ALGORITHM_MAP, $algorithmIdentifier, 'The specified algorithm identifier is not supported');
        return self::$COSE_ALGORITHM_MAP[$algorithmIdentifier];
    }

    public static function getHashAlgorithmFor($algorithmIdentifier)
    {
        Assertion::keyExists(self::$COSE_HASH_MAP, $algorithmIdentifier, 'The specified algorithm identifier is not supported');
        return self::$COSE_HASH_MAP[$algorithmIdentifier];
    }

    public static function getAlgorithm($identifier): Algorithm
    {
        $algs = static::getAlgorithms();
        Assertion::keyExists($algs, $identifier, 'The specified algorithm identifier is not supported');

        return $algs[$identifier];
    }

    /**
     * @return Algorithm[]
     */
    public static function getAlgorithms(): array
    {
        return [
            Mac\HS256::identifier() => new Mac\HS256(),
            Mac\HS384::identifier() => new Mac\HS384(),
            Mac\HS512::identifier() => new Mac\HS512(),
            RSA\RS256::identifier() => new RSA\RS256(),
            RSA\RS384::identifier() => new RSA\RS384(),
            RSA\RS512::identifier() => new RSA\RS512(),
            RSA\PS256::identifier() => new RSA\PS256(),
            RSA\PS384::identifier() => new RSA\PS384(),
            RSA\PS512::identifier() => new RSA\PS512(),
            ECDSA\ES256::identifier() => new ECDSA\ES256(),
            ECDSA\ES384::identifier() => new ECDSA\ES384(),
            ECDSA\ES512::identifier() => new ECDSA\ES512(),
            EdDSA\EdDSA::identifier() => new EdDSA\EdDSA(),
        ];
    }
}
