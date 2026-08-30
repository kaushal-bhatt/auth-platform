package com.authplatform.auth.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * What the login page asks for once the user has authenticated.
 * <p>
 * Snake-case on the wire, unlike the rest of this API: these are the parameter names of the
 * authorization-code flow, and using them makes the shape of the exchange recognisable to
 * anyone who has seen one before. There is no {@code user_id} here on purpose — the acting user
 * is read from the verified access token, never from the body, or a caller could mint codes
 * for other people's accounts.
 */
public record SsoCodeRequest(
    @JsonProperty("client_id") String clientId,
    @JsonProperty("redirect_uri") String redirectUri,
    @JsonProperty("state") String state
) {
}
