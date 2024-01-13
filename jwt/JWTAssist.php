<?php
/**
 * @copyright   ©2024 Maatify.dev
 * @Liberary    JWT
 * @Project     JWT
 * @author      Mohamed Abdulalim (megyptm) <mohamed@maatify.dev>
 * @since       2024-01-13 09:27 AM
 * @see         https://www.maatify.dev Maatify.com
 * @link        https://github.com/Maatify/jwt view project on GitHub
 * @link        https://github.com/Maatify/Functions (maatify/functions)
 * @link        https://github.com/Maatify/Json (maatify/json)
 * @link        https://github.com/Maatify/Logger (maatify/logger)
 * @link        https://github.com/firebase/php-jwt (firebase/php-jwt)
 * @note        This Project using for JWT Encryptions.
 * @note        This Project extends other libraries firebase/php-jwt, maatify/logger, maatify/json, maatify/post-functions.
 *
 * @note        This program is distributed in the hope that it will be useful - WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.
 *
 */
namespace JwtHandler;

use Exception;
use Maatify\Logger\Logger;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use stdClass;

abstract class JWTAssist
{
    protected string $secretKey;

    protected string $algo = 'HS256';

    /**

        use Firebase\JWT\JWT;
        use Firebase\JWT\Key;

        $key = 'example_key';
        $payload = [
        'iss' => 'http://example.org',
        'aud' => 'http://example.com',
        'iat' => 1356999524,
        'nbf' => 1357000000
        ];

        /*
         * IMPORTANT:
         * You must specify supported algorithms for your application. See
         * https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-40
         * for a list of spec-compliant algorithms.

        $jwt = JWT::encode($payload, $key, 'HS256');
        $decoded = JWT::decode($jwt, new Key($key, 'HS256'));

        print_r($decoded);


         NOTE: This will now be an object instead of an associative array. To get
         an associative array, you will need to cast it as such:


        $decoded_array = (array) $decoded;

        /*
         * You can add a leeway to account for when there is a clock skew times between
         * the signing and verifying servers. It is recommended that this leeway should
         * not be bigger than a few minutes.
         *
         * Source: http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html#nbfDef

        JWT::$leeway = 60; // $leeway in seconds
        $decoded = JWT::decode($jwt, new Key($key, 'HS256'));

     */

    protected function Encode($issuer, $timeout, array $data): string
    {
        $data['iat'] = time();
        $data['nbf'] = $data['iat']-1;
        $data['exp'] = $data['iat']+$timeout;
        $data['iss'] = $issuer;
        $data['ip'] = $_SERVER['REMOTE_ADDR'] ?? "";
        if($timeout == 60*60*24*30) {
            $data['remember'] = true;
        }

        try {
            $jwt = JWT::encode($data, $this->secretKey,$this->algo);
        } catch (Exception $e) { // Also tried JwtException
            Logger::RecordLog($e, 'jwtEncode_error_'.$issuer);
            $jwt = false;
        }
        return $jwt;
    }

    protected function Decode($jwt): stdClass
    {
        try {
            $arr = JWT::decode($jwt, new Key($this->secretKey, $this->algo));
        } catch (Exception $e) { // Also tried JwtException
            Logger::RecordLog($e, 'jwtDecode_error_');
            $arr = new stdClass();
        }
        return $arr;
    }


}