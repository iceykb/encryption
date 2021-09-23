<?php

namespace Icebing\Encryption;

class AES
{

    /**
     * var string $method 密码学加解密方法
     */
    protected static $method;

    /**
     * var string $key 加解密的密钥
     */
    protected static $key;

    /**
     * var string $iv 初始化向量非NULL
     */
    protected static $iv;

    protected static $options;

    public function __construct($key, $iv, $method = 'AES-256-CBC', $options = 0)
    {
        self::$key = $key;
        self::$method = $method;
        self::$iv = $iv;
        self::$options = $options;
    }

    public function encrypt($data)
    {
        return openssl_encrypt($data, self::$method, self::$key, 0, $this->getIv());
    }

    public function decrypt($encrypted)
    {
        return openssl_decrypt($encrypted, self::$method, self::$key, 0, $this->getIv());
    }

    public function getIv()
    {
        $ivLen = openssl_cipher_iv_length(self::$method);
        $iv = '';
        if ($ivLen) {
            $iv = substr(self::$iv, 0, $ivLen);
        }
        return $iv;
    }

}