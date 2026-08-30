package com.authplatform.auth.controller;

import com.authplatform.auth.dto.SsoCodeRequest;
import com.authplatform.auth.dto.SsoCodeResponse;
import com.authplatform.auth.dto.SsoTokenRequest;
import com.authplatform.auth.dto.TokenResponse;
import com.authplatform.auth.service.SsoService;
import com.authplatform.auth.util.VerifiedCaller;
import com.authplatform.jwt.annotation.JwtTokenVerification;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

/**
 * Single sign-on for other sites, as an authorization-code redirect flow.
 *
 * <pre>
 *   1. wekt.in/admin has no session          -> 302 to /sso/authorize?client_id&redirect_uri&state
 *   2. GET  /sso/authorize                   -> validates, serves the login page
 *   3. the page authenticates the user with the ordinary passkey endpoints
 *   4. POST /sso/code   (Bearer access token) -> one-time code, as a redirect URL
 *   5. the browser lands back on the relying party with ?code&amp;state
 *   6. POST /sso/token  (client secret)       -> the code is exchanged for tokens, server to server
 * </pre>
 *
 * The access token minted in step 3 never leaves this origin — it lives in the login page's
 * memory just long enough to prove who is asking for a code. What crosses to the other site is
 * the code, and a code is worthless without the client secret.
 */
@RestController
@RequestMapping("/sso")
@RequiredArgsConstructor
public class SsoController {

    private final SsoService ssoService;

    /**
     * Read once at startup rather than per request. It is a small static file and this avoids a
     * disk read on a user-facing path; it is also served directly instead of forwarded to the
     * static resource handler, so that the client and redirect URI are validated <em>before</em>
     * anything is rendered and the outcome does not depend on view-resolution order.
     */
    private String loginPage;

    @PostConstruct
    void loadLoginPage() throws IOException {
        try (InputStream in = new ClassPathResource("static/sso.html").getInputStream()) {
            this.loginPage = new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    /**
     * The page the user actually sees.
     * <p>
     * Validation here is a courtesy — {@link SsoService#issueCode} re-checks everything
     * authoritatively — but it means a misconfigured relying party fails immediately and
     * visibly, rather than after the user has gone to the trouble of authenticating.
     * <p>
     * Note what this does <em>not</em> do on failure: redirect. The redirect URI is the
     * untrusted part of the request, so an invalid one is reported here, on this origin, and
     * never used to send the browser anywhere.
     */
    @GetMapping(value = "/authorize", produces = MediaType.TEXT_HTML_VALUE)
    public String authorize(
        @RequestParam("client_id") String clientId,
        @RequestParam("redirect_uri") String redirectUri
    ) {
        ssoService.validateAuthorizeRequest(clientId, redirectUri);
        return loginPage;
    }

    /**
     * Mints the one-time code. Protected by auth-jwt-lib, so an unauthenticated request never
     * reaches the method body, and the user id comes from the verified claims rather than the
     * request — the same rule {@code PasskeyController} follows.
     */
    @PostMapping("/code")
    @JwtTokenVerification
    public SsoCodeResponse code(HttpServletRequest request, @RequestBody SsoCodeRequest body) {
        Long userId = VerifiedCaller.requireUserId(request);
        return new SsoCodeResponse(
            ssoService.issueCode(userId, body.clientId(), body.redirectUri(), body.state()));
    }

    /**
     * Server-to-server code exchange. Deliberately not {@code @JwtTokenVerification}: the caller
     * here is the relying party's backend, which has no user token — it authenticates with its
     * client secret instead.
     */
    @PostMapping("/token")
    public TokenResponse token(@RequestBody SsoTokenRequest body) {
        return ssoService.exchangeCode(
            body.clientId(), body.clientSecret(), body.code(), body.redirectUri());
    }
}
