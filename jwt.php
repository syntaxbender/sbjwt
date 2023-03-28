<?php
require_once('jwtexception.php');
/*
TODO aud instance içerisinde değil de sign ile beraber de verilebilmeli.
*/
class Jwt{
    private $secret = null;
    private $issuer = null;
    private $audience = null;
    private $defaultPayload = null;
    private $header = null;
    private $payload = null;
    function __construct($secret,$issuer,$audience){
        $this->secret = $secret;
        $this->issuer = $issuer;
        $this->audience = $audience;
        $this->defaultPayload = [
            'iss'=>$issuer,
            'aud'=>$audience,
            'iat'=>time()
        ];
    }
    private function forceInt($data){
        if(is_int($data) === false){
            if(preg_match('/^[0-9]+$/',$data) === false)
                throw new JwtException('JWT_MISCONFIGURED');
            return intval($data);
        }
        return $data;
        
    }
    private function generatePayload($subject,$expiration,$notBefore=null,$jwtId=null,$additional){
        $this->header = [
            'alg' => 'HS256',
            'typ' => 'JWT'
        ];

        $nbf = ($notBefore === null)? time() : $this->forceInt($notBefore);
        $expiration = $this->forceInt($expiration);
        if($expiration<$nbf) throw new JwtException('JWT_EXP_MISCONFIGURED');
        
        $sub = $subject;
        $exp = $expiration;
        $jti = ($jwtId === null)? uniqid() : $jwtId;

        $payload = [
            'sub' => $sub,
            'exp' => $exp,
            'nbf' => $nbf,
            'jti' => $jti
        ];
        $this->payload = array_merge($this->defaultPayload,$payload,$additional);
    }
    private function base64urlEncode($data){
        return str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($data));
    }
    private function base64urlDecode($data) {
        return base64_decode(str_replace(['-','_'], ['+','/'], $data));
    }
    private function secureJsonDecode($data){
        try{
            $jsonData = json_decode($data, true, JSON_THROW_ON_ERROR);
        }catch(JsonException $e){
            throw new JwtException('JWT_DEFECTED_DATA');
        }
        return $jsonData;
    }
    public function signHmac($subject,$expiration,$notBefore=null,$jwtId=null,$additional){
        $this->generatePayload($subject,$expiration,$notBefore,$jwtId,$additional);
        $header = $this->base64urlEncode(json_encode($this->header));
        $payload = $this->base64urlEncode(json_encode($this->payload));
        $jwt = $header.'.'.$payload;
        $signature = $this->base64urlEncode(hash_hmac('sha512', $jwt, $this->secret, true));
        return $jwt.'.'.$signature;
    }
    public function verify($token){
        $tokenParts = explode('.', $token);
        $header = $this->secureJsonDecode($this->base64urlDecode($tokenParts[0]), true);
        $payload = $this->secureJsonDecode($this->base64urlDecode($tokenParts[1]), true);
        $signature = $this->base64urlDecode($tokenParts[2]);
        if(array_key_exists('nbf',$payload) === false || array_key_exists('exp',$payload) === false) throw new JwtException('JWT_VERIFICATION_MISSING_DATA');
        
        $this->verifyExp($payload);
        $this->verifyNbf($payload);
        $this->verifyAud($payload);
        $this->verifyIss($payload);

        switch ($header['alg']){
            case "HS256":
                $encodedRawTokenData = $tokenParts[0].'.'.$tokenParts[1];
                return $this->verifyHmac($signature,$encodedRawTokenData);
                break;
            default:
                throw new JwtException('JWT_UNSUPPORTED_ALG');
        }
    }
    private function verifyHmac($tokenSignature,$encodedRawTokenData) {
        $generatedSignature = hash_hmac('sha512', $encodedRawTokenData, $this->secret, true);
        return (hash_equals($generatedSignature, $tokenSignature));
    }
    private function verifyAud($payload){
        if(array_key_exists('aud',$payload) === false) throw new JwtException('JWT_VERIFICATION_AUD_FAIL');
        if(is_array($this->audience) && array_diff((array) $payload['aud'], $this->audience) === false) throw new JwtException('JWT_VERIFICATION_AUD_FAIL');
        if($payload['aud'] != $this->audience) throw new JwtException('JWT_VERIFICATION_AUD_FAIL');
    }
    private function verifyIss($payload){
        if(array_key_exists('iss',$payload) === false || $payload['iss'] != $this->issuer) throw new JwtException('JWT_VERIFICATION_ISS_FAIL');
    }
    private function verifyNbf($payload){
        if($this->forceInt($payload['nbf'])>time()) throw new JwtException('JWT_VERIFICATION_NBF_FAIL');

    }
    private function verifyExp($payload){
        if($this->forceInt($payload['exp'])<time()) throw new JwtException('JWT_VERIFICATION_EXP_FAIL');

    }

}
$jwt = new Jwt("123","sso.google.com",["images.google.com","domains.google.com"]);
$ok = $jwt->signHmac("asd",time()+99999,time(),null,["ok"=>"ok"]);
$bok = $jwt->verify($ok);
var_dump($bok);
?>