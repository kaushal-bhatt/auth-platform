package com.authplatform.auth.dto;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link TokenResponse} is the highest-value object in the system: it carries a live access token
 * and a 30-day refresh token. As a bare record its generated {@code toString()} printed both in
 * full, and {@code GlobalExceptionHandler} logs complete stack traces — so any future code that
 * interpolated this DTO would have written a replayable bearer credential into the logs in
 * plaintext. This pins the masking so removing the override cannot go unnoticed.
 */
class TokenResponseTest {

    private static final String ACCESS_TOKEN = "eyJhbGciOiJSUzI1NiJ9.header-payload.access-signature";
    private static final String REFRESH_TOKEN = "cmVmcmVzaC10b2tlbi1zZWNyZXQtdmFsdWU";

    @Test
    void toStringMasksBothTokensAndKeepsExpiresInVisible() {
        TokenResponse response = new TokenResponse(ACCESS_TOKEN, REFRESH_TOKEN, 900L);

        String result = response.toString();

        assertThat(result).doesNotContain(ACCESS_TOKEN);
        assertThat(result).doesNotContain(REFRESH_TOKEN);
        assertThat(result).contains("accessToken=***");
        assertThat(result).contains("refreshToken=***");
        // expiresIn is a non-secret duration and is the most useful field when diagnosing
        // token-lifetime problems, so it stays readable.
        assertThat(result).contains("expiresIn=900");
    }

    /**
     * Masking must not be implemented by blanking the components themselves: Tasks 11 and 15
     * consume these accessors and Jackson serialises them onto the wire.
     */
    @Test
    void accessorsStillReturnTheRealCredentialValues() {
        TokenResponse response = new TokenResponse(ACCESS_TOKEN, REFRESH_TOKEN, 900L);

        assertThat(response.accessToken()).isEqualTo(ACCESS_TOKEN);
        assertThat(response.refreshToken()).isEqualTo(REFRESH_TOKEN);
        assertThat(response.expiresIn()).isEqualTo(900L);
    }
}
