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
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Maatify\Functions\GeneralFunctions;
use Maatify\Logger\Logger;
use stdClass;

abstract class JwtHandler extends JWT
{
    protected string $algo = 'HS256';
    //    protected $algo = 'HS384';
    //    protected $algo = 'HS512';
    protected string $secretKey;

    protected string $ssl_secret;
    protected string $ssl_key;
    protected string $ssl_cipher_algo;
    protected int $timeout = 20;

    public function __construct(){
        $this->secretKey = openssl_encrypt($this->ssl_secret, $this->ssl_cipher_algo, $this->ssl_key);
    }

    public function DeHash($jwt): stdClass
    {
        if($decode = $this->JwtDecode($jwt)){
            if(!empty($decode->iss)) {
                if ($decode->iss == GeneralFunctions::HostUrl()
                    && $decode->nbf < time()
                    && $decode->ip == ($_SERVER['REMOTE_ADDR'] ?? '')
                ) {
                    if (isset($decode->next)) {
                        if ($decode->next == GeneralFunctions::CurrentAction()) {
                            return $decode;
                        }
                    } else {
                        return $decode;
                    }
                }
            }
        }
        return new stdClass();
    }

    public function DeHashValidation($jwt): stdClass
    {
        if($decode = $this->JwtDecode($jwt)){
            if(!empty($decode->iss)) {
                if ($decode->iss == GeneralFunctions::HostUrl()
                    && $decode->nbf < time()
                    && $decode->exp > time()
                    && $decode->ip == ($_SERVER['REMOTE_ADDR'] ?? '')
                ) {
                    if (isset($decode->next)) {
                        if ($decode->next == GeneralFunctions::CurrentAction()) {
                            return $decode;
                        }
                    } else {
                        return $decode;
                    }
                }
            }
        }
        return new stdClass();
    }

    private function JwtDecode($jwt): stdClass
    {
        try {
            $arr = self::decode($jwt, new Key($this->secretKey, $this->algo));
        } catch (Exception $e) { // Also tried JwtException
            Logger::RecordLog($e, 'jwtDecode_error_');
            $arr = new stdClass();
        }
        return $arr;
    }



/** ========================================== Hashing and Encoding ========================================== */
    public function JwtHash(array|string $array): string
    {
        if(!is_array($array)) {
            $arr['token'] = $array;
        }
        else {
            $arr = $array;
        }
        return $this->Hash(GeneralFunctions::HostUrl(),$this->timeout*60, $arr);
    }

    private function Hash($issuer, $timeout, array $data): string
    {
        return $this->JwtEncode($issuer, $timeout, $data);
    }

    private function JwtEncode($issuer, $timeout, array $data): string
    {
        $data['iat'] = time();
        $data['nbf'] = $data['iat']-1;
        $data['exp'] = $data['iat']+$timeout;
        $data['iss'] = $issuer;
        $data['ip'] = $_SERVER['REMOTE_ADDR'] ?? '';
        if($timeout == 60*60*24*30) {
            $data['remember'] = true;
        }

        try {
            $jwt = self::encode($data, $this->secretKey,$this->algo);
        } catch (Exception $e) { // Also tried JwtException
            Logger::RecordLog($e, 'jwtEncode_error_'.$issuer);
            $jwt = false;
        }
        return $jwt;
    }
}