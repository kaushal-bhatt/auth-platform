package com.authplatform.auth.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * The relying party's server-to-server request exchanging a code for tokens. The client secret
 * proves the request really comes from that party, which is what makes it safe for the code
 * itself to have travelled through the browser.
 */
public record SsoTokenRequest(
    @JsonProperty("client_id") String clientId,
    @JsonProperty("client_secret") String clientSecret,
    @JsonProperty("code") String code,
    @JsonProperty("redirect_uri") String redirectUri
) {

    /**
     * Masks the two secrets. A record's generated {@code toString()} prints every component,
     * and {@code GlobalExceptionHandler} logs full stack traces — so any future code that
     * interpolated this into a log line or exception message would write the client secret and a
     * live authorisation code to the logs in plaintext. {@code TokenResponse} and
     * {@code LoginRequest} do the same.
     */
    @Override
    public String toString() {
        return "SsoTokenRequest[clientId=" + clientId + ", clientSecret=***, code=***, redirectUri="
            + redirectUri + "]";
    }
}
