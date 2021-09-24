<?php


namespace Iceykb\Encryption;


use http\Client;

class RSA
{
    const RSA_ALGORITHM_KEY_TYPE = OPENSSL_KEYTYPE_RSA;

    protected $publicKey;
    protected $privateKey;
    protected $keyLen;
    public function __construct($pubKey, $priKey = null)
    {
        $this->publicKey = $pubKey;
        $this->privateKey = $priKey;

        $pubId = openssl_get_publickey($this->publicKey);
        $this->keyLen = openssl_pkey_get_details($pubId)['bits'];
    }

    /**
     * 生成公 私钥
     * @param int $key_size
     * @return array
     */
    public static function createKeys($keySize = 2048)
    {
        $config = [
            'private_key_bits' => $keySize,
            'private_key_type' => self::RSA_ALGORITHM_KEY_TYPE
        ];
        $res = openssl_pkey_new($config);
        openssl_pkey_export($res, $privateKey);

        $public_key_detail = openssl_pkey_get_details($res);
        $public_key = $public_key_detail["key"];

        return [
            "public_key" => $public_key,
            "private_key" => $privateKey,
        ];
    }

    /**
     * 公钥加密
     * @param $data
     * @return string
     */
    public function publicEncrypt($data)
    {
        $encrypted = '';
        $part_len = $this->keyLen / 8 - 11;
        $parts = str_split($data, $part_len);

        foreach ($parts as $part) {
            $encrypted_temp = '';
            openssl_public_encrypt($part, $encrypted_temp, $this->publicKey);
            $encrypted .= $encrypted_temp;
        }

        return base64_encode($encrypted);
    }

    /**
     * 私钥解密
     * @param $encrypted
     * @return string
     */
    public function privateDecrypt($encrypted)
    {
        $decrypted = "";
        $part_len = $this->keyLen / 8;
        $base64_decoded = base64_decode($encrypted);
        $parts = str_split($base64_decoded, $part_len);

        foreach ($parts as $part) {
            $decrypted_temp = '';
            openssl_private_decrypt($part, $decrypted_temp,$this->privateKey);
            $decrypted .= $decrypted_temp;
        }
        return $decrypted;
    }

    /**
     * 私钥加密
     * @param $data
     * @return string
     */
    public function privateEncrypt($data)
    {
        $encrypted = '';
        $part_len = $this->keyLen / 8 - 11;
        $parts = str_split($data, $part_len);

        foreach ($parts as $part) {
            $encrypted_temp = '';
            openssl_private_encrypt($part, $encrypted_temp, $this->privateKey);
            $encrypted .= $encrypted_temp;
        }

        return base64_encode($encrypted);
    }

    /**
     * 公钥解密
     * @param $encrypted
     * @return string
     */
    public function publicDecrypt($encrypted)
    {
        $decrypted = "";
        $part_len = $this->keyLen / 8;
        $base64_decoded = base64_decode($encrypted);
        $parts = str_split($base64_decoded, $part_len);

        foreach ($parts as $part) {
            $decrypted_temp = '';
            openssl_public_decrypt($part, $decrypted_temp,$this->publicKey);
            $decrypted .= $decrypted_temp;
        }
        return $decrypted;
    }

}