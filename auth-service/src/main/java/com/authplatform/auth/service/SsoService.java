package com.authplatform.auth.service;

import com.authplatform.auth.dto.TokenResponse;

/**
 * The authorisation-code redirect flow that lets another site log a user in through this
 * service.
 * <p>
 * Shape, and why: the browser is sent back to the relying party carrying a <em>code</em>, not a
 * token. A redirect URL is written to browser history, sent on in the {@code Referer} header of
 * the next request, and recorded by every proxy in between — so whatever travels there must be
 * near-worthless. A code is: single-use, alive for about a minute, and unredeemable without the
 * client secret, which never leaves the relying party's server. An access token in the same
 * position would be a live credential in all of those logs.
 */
public interface SsoService {

    /**
     * Checks that a browser-facing authorize request names a registered client and one of its
     * registered redirect URIs, before any login page is shown.
     * <p>
     * This is a courtesy, not the security boundary — {@link #issueCode} re-checks everything
     * authoritatively. It exists so a misconfigured relying party fails immediately and visibly
     * instead of after the user has authenticated.
     *
     * @throws com.authplatform.auth.exception.CustomException 400 if the client or redirect URI
     *                                                         is not registered
     */
    void validateAuthorizeRequest(String clientId, String redirectUri);

    /**
     * Mints a one-time code for an already-authenticated user and returns the full URL the
     * browser should be sent to.
     *
     * @param userId the caller's id, taken from their verified access token — never from the
     *               request body, or a caller could mint codes for other people
     * @throws com.authplatform.auth.exception.CustomException 400 for an unregistered client or
     *                                                         redirect URI, 403 if the user does
     *                                                         not hold the role the client requires
     */
    String issueCode(Long userId, String clientId, String redirectUri, String state);

    /**
     * Redeems a code for tokens, authenticating the relying party by its secret.
     *
     * @throws com.authplatform.auth.exception.CustomException 401 for a bad client secret, 400
     *                                                         for a code that is unknown, expired,
     *                                                         already redeemed, or bound to a
     *                                                         different client or redirect URI
     */
    TokenResponse exchangeCode(String clientId, String clientSecret, String code, String redirectUri);
}
