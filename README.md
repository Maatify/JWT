[![Current version](https://img.shields.io/packagist/v/maatify/jwt)][pkg]
[![Packagist PHP Version Support](https://img.shields.io/packagist/php-v/maatify/jwt)][pkg]
[![Monthly Downloads](https://img.shields.io/packagist/dm/maatify/jwt)][pkg-stats]
[![Total Downloads](https://img.shields.io/packagist/dt/maatify/jwt)][pkg-stats]
[![Stars](https://img.shields.io/packagist/stars/maatify/jwt)](https://github.com/maatify/jwt/stargazers)

[pkg]: <https://packagist.org/packages/maatify/jwt>
[pkg-stats]: <https://packagist.org/packages/maatify/jwt/stats>

# JWT

maatify.dev JWT handler, known by our team


# Installation

```shell
composer require maatify/jwt
```

# To Use
Create Class Extend JWTAssist


```php
<?php

use JwtHandler\JWTAssist;

class JwtCheck extends JWTAssist
{
    protected string $ssl_secret = '6GSSLr%70SecrectH1IAbtestzoHB0!0bI';
    protected string $ssl_key = 'M7u9SSLR3&0testwXRAIbKEYGoYJjK';
    protected string $ssl_cipher_algo = 'AES-128-ECB';

    public function Hash(): string
    {
        return $this->Encode('www.maatify.dev', 60, ['array of data']);
    }

    public function Dehash(string $jwt_token): \stdClass
    {
        return $this->Decode($jwt_token);
    }
}
