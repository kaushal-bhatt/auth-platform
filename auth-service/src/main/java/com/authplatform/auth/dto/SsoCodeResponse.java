package com.authplatform.auth.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * The URL the browser should be sent to, carrying the one-time code and the caller's
 * {@code state}.
 * <p>
 * Returned as JSON for the page to navigate to, rather than as a 302 the browser follows
 * itself: the page needs to be able to show an error in place when something is wrong, and a
 * redirect issued from a fetch() would be followed silently with nothing to display.
 */
public record SsoCodeResponse(@JsonProperty("redirect_url") String redirectUrl) {
}
