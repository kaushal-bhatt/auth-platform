package com.authplatform.auth.dto;

import jakarta.validation.constraints.NotBlank;

/**
 * Carries the caller's refresh token to {@code POST /auth/refresh}. {@code @NotBlank} rejects a
 * null/blank token with a clean 400 before it ever reaches {@link com.authplatform.auth.service.TokenService#refresh},
 * which would otherwise treat it the same as any other invalid token and return a 401.
 */
public record RefreshRequest(@NotBlank String refreshToken) {

    /**
     * Masks the refresh token so that any future request-logging filter, debug statement, or
     * error message that interpolates this DTO cannot leak a live, replayable 30-day credential.
     * Mirrors {@code LoginRequest}, {@code RegisterRequest}, and {@code TokenResponse}'s
     * toString overrides.
     */
    @Override
    public String toString() {
        return "RefreshRequest[refreshToken=***]";
    }
}
