package com.authplatform.auth.dto;

/**
 * The credential pair returned by login and refresh.
 * <p>
 * Note for future maintainers: the component names and their order are a wire contract —
 * Jackson serialises {@code accessToken}/{@code refreshToken}/{@code expiresIn} onto the HTTP
 * response and downstream tasks consume them. Do not rename or reorder them.
 */
public record TokenResponse(String accessToken, String refreshToken, long expiresIn) {

    /**
     * Masks both credentials. A bare record's generated {@code toString()} prints every
     * component in full, which for this type means a live access token and a 30-day refresh
     * token. {@code GlobalExceptionHandler} logs full stack traces, so any future code that
     * interpolates this DTO into a log line, exception message, or debug statement would write a
     * replayable bearer credential to the logs in plaintext. {@code LoginRequest} and
     * {@code RegisterRequest} override {@code toString()} for the same reason.
     * <p>
     * {@code expiresIn} is left visible: it is a non-secret duration and is the field most
     * useful when diagnosing token-lifetime problems.
     */
    @Override
    public String toString() {
        return "TokenResponse[accessToken=***, refreshToken=***, expiresIn=" + expiresIn + "]";
    }
}
