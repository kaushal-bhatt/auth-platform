package com.authplatform.auth.dto;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Mirrors {@code LoginRequestTest} and {@code RegisterRequestTest}. {@link RefreshRequest} carries
 * a live, replayable 30-day refresh token, so nothing must assume the default record
 * {@code toString()} would ever be safe to log.
 */
class RefreshRequestTest {

    @Test
    void toStringDoesNotContainTheRefreshToken() {
        RefreshRequest request = new RefreshRequest("live-refresh-token-value");

        String result = request.toString();

        assertThat(result).doesNotContain("live-refresh-token-value");
        assertThat(result).contains("refreshToken=***");
    }

    @Test
    void accessorStillReturnsTheRealRefreshToken() {
        RefreshRequest request = new RefreshRequest("live-refresh-token-value");

        assertThat(request.refreshToken()).isEqualTo("live-refresh-token-value");
    }
}
