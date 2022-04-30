<?php

class JWT {


    /**
     * leeway time to account for clock skew
     */
    private static $leeway = 0;
    
    /**
     * supported algorithms
     * default HS256
     */

    private static $supportedAlgs = [
        "HS256" => ["hash_hmac", "SHA256"],
        "HS384" => ["hash_hmac", "SHA384"],
        "HS512" => ["hash_hmac", "SHA512"]
    ];

    /**
     * Returning base64 url safe string for a given input
     * 
     * @param string $input The input string to encode
     * 
     * return string encoded input
     */
    private static function urlSafeBase64Encode(string $input) 
    {
        return \str_replace('=', '', \strtr(\base64_encode($input), '+/', '-_'));
    }


    /**
     * Returning decoded string for a url safe base64 encoded input
     * 
     * @param string $input The encrypted string input to decode
     * 
     * return string decoded input
     */
    private static function urlSafeBase64Decode(string $input)
    {
        $charCount = 4;
        $remain = strlen($input) % $charCount;
        if($remain) 
        {
            $equalCount = $charCount - $remain;
            $input .= str_repeat('=', $equalCount);
        }
        return base64_decode(strtr($input, '-_', '+/'));
    }


    /**
     * Signing a given string with a provided secret key using HS512 algo
     * 
     * @param string $msg The message to sign
     * @param string $key The secret key
     * @param string $alg Supported algorithm 
     *                          default = HS256
     *                          supported = HS256, HS384, HS512
     * 
     * return string encrypted message
     */

    public static function sign(string $msg, string $key, string $alg = "HS256")   
    {
        if(empty(self::$supportedAlgs[$alg]))
        {
            throw new Exception('Algo not supported!');
        }
        list($function, $algorithm) = self::$supportedAlgs[$alg];
        if(!function_exists($function))
        {
            throw new Exception('function not exist');
        }
        return $function($algorithm, $msg, $key, true);
    }



    /**
     * Encoding a given payload to a jwt token
     * 
     * @param mixed $payload The payload (can be string, array or an object)
     * @param string key The secret key
     * @param string alg Algorithm for encrypting signature (deafult HS256)
     * @param array head External header elements
     * 
     * return jwt token
     */
    public static function encode(mixed $payload, string $key, string $alg = "HS256", array $head = null)
    {
        $header = ["typ" => "JWT", "alg" => $alg];
        if(isset($head) && is_array($head))
        {
            $header = array_merge($head, $header);
        }
        $segments = [];
        $segments[] = self::urlSafeBase64Encode(json_encode($header));
        $segments[] = self::urlSafeBase64Encode(json_encode($payload));
        $inputForSigning = implode('.', $segments);
        $signature = self::sign($inputForSigning, $key, $alg);
        $segments[] = self::urlSafeBase64Encode($signature);
        $jwt = implode('.', $segments);
        return $jwt;
    }


    /**
     * Verify a given message with the signature
     * 
     * @param string msg The message to verify against signature
     * @param string signature The signature
     * @param string key The secret key
     * @param string alg The algorithm
     * 
     * return true if msg verify with the signature, otherwise false 
     */
    public static function verify(string $msg, string $signature, string $key, string $alg) 
    {
        if(empty(self::$supportedAlgs[$alg])) 
        {
            throw new Exception("Algo not supported");
        }
        list($function, $algorithm) = self::$supportedAlgs[$alg];
        if(!function_exists($function))
        {
            throw new Exception("Function not exists");
        }
        $comp = $function($algorithm, $msg, $key, true);
        if(!function_exists('hash_equals'))
        {
            throw new Exception("Function not exists");
        }
        return hash_equals($signature, $comp);
    }


    /**
     * Decode a given jwt token using the provided secret key
     *
     * @param $jwt The jwt token to decode
     * @param $key The secret key
     * 
     * return The payload that include in the provided jwt token
     */
    public static function decode(string $jwt, string $key)
    {
        $timestamp = time();
        if(empty($key)) 
        {
            throw new Exception("Key empty!");
        } 

        $tokens = explode('.', $jwt);

        if(count($tokens) != 3)
        {
            throw new Exception("Invalid token count");
        }
        list($encodedHeader, $encodedPayload, $encodedSignature) = $tokens;
        $header = json_decode(self::urlSafeBase64Decode($encodedHeader));
        $payload = json_decode(self::urlSafeBase64Decode($encodedPayload));
        $signature = self::urlSafeBase64Decode($encodedSignature);
        
        if($header === null || $payload === null)
        {
            throw new Exception("Invalid encoding");
        }

        if($signature === false)
        {
            throw new Exception("Invalid signature encoding");
        }

        if(empty($header->alg))
        {
            throw new Exception("Empty Algo");
        }

        if(empty(self::$supportedAlgs[$header->alg]))
        {
            throw new Exception("Algo not supported");
        }

        if(!self::verify("$encodedHeader.$encodedPayload", $signature, $key, $header->alg))
        {
            throw new Exception("Signature verification failed");
        }

        if(isset($payload->nbf) && $payload->nbf > ($timestamp + self::$leeway))
        {
            throw new Exception("Cannot handle yet");
        }

        if(isset($payload->iat) && $payload->iat > ($timestamp + self::$leeway))
        {
            throw new Exception("Cannot handle token");
        }

        if(isset($payload->exp) && ($timestamp - self::$leeway) >= $payload->exp)
        {
            throw new Exception("Expired token");
        }

        return $payload;
    }

}
