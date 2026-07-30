package com.authplatform.auth.dto;

import java.util.List;

public record PasskeyRegisterInitResponse(
    String challenge,
    String userId,
    String userName,
    String rpId,
    String rpName,
    List<PubKeyCredParam> pubKeyCredParams,
    long timeoutMillis
) {
    public record PubKeyCredParam(String type, int alg) {
    }
}
