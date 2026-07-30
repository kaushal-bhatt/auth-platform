package com.authplatform.jwt.model;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class JwtVerificationResultTest {

    @Test
    void successCarriesClaimsAndNoError() {
        JwtClaims claims = new JwtClaims("123", "a@b.com", "auth-service", "web", "sess-1", null, null);

        JwtVerificationResult result = JwtVerificationResult.success(claims);

        assertThat(result.valid()).isTrue();
        assertThat(result.errorMessage()).isNull();
        assertThat(result.claims()).isEqualTo(claims);
    }

    @Test
    void failureCarriesMessageAndNoClaims() {
        JwtVerificationResult result = JwtVerificationResult.failure("jwt token has expired");

        assertThat(result.valid()).isFalse();
        assertThat(result.errorMessage()).isEqualTo("jwt token has expired");
        assertThat(result.claims()).isNull();
    }
}
