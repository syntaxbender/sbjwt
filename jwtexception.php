<?php
class JwtException extends LogicException {
    private $types = [
        "JWT_UNKNOWN"=> 7000,
        "JWT_EXPIRED"=> 7001,
        "JWT_DROP"=> 7002,
        "JWT_AUDIENCE_MISMATCH"=> 7003,
        "JWT_ISSUER_MISMATCH"=> 7004,
        "JWT_MISCONFIGURED"=> 7005,
        "JWT_EXP_MISCONFIGURED"=> 7006,
        "JWT_UNSUPPORTED_ALG"=> 7007,
        "JWT_VERIFICATION_EXP_FAIL"=> 7008,
        "JWT_VERIFICATION_NBF_FAIL"=> 7010,
        "JWT_VERIFICATION_ISS_FAIL"=> 7011,
        "JWT_VERIFICATION_AUD_FAIL"=> 7011,
        "JWT_VERIFICATION_MISSING_DATA"=> 7009,
        "JWT_DEFECTED_DATA"=> 7012,
    ];
    function __construct($type, Throwable $previous = null) {
        if(array_key_exists($type,$this->types)){
            parent::__construct($type, $this->types[$type], $previous);
            
        }else{
            parent::__construct("JWT_UNKNOWN");
        }
    }
}
?>