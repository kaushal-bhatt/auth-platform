package com.authplatform.jwt.model;

public record JwtVerificationResult(boolean valid, String errorMessage, JwtClaims claims) {

    public static JwtVerificationResult success(JwtClaims claims) {
        return new JwtVerificationResult(true, null, claims);
    }

    public static JwtVerificationResult failure(String errorMessage) {
        return new JwtVerificationResult(false, errorMessage, null);
    }
}
