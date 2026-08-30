package com.authplatform.auth.service.impl;

import com.authplatform.auth.config.SsoProperties;
import com.authplatform.auth.dto.TokenResponse;
import com.authplatform.auth.entity.SsoAuthCodeEntity;
import com.authplatform.auth.entity.UserEntity;
import com.authplatform.auth.exception.CustomException;
import com.authplatform.auth.repository.SsoAuthCodeRepository;
import com.authplatform.auth.repository.UserRepository;
import com.authplatform.auth.service.TokenService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The security properties of the redirect flow, pinned.
 * <p>
 * Most of these assert a refusal. That is the point: every one of them corresponds to a way the
 * flow hands out someone's session if the check is dropped, and none of them is visible in
 * ordinary use — a working login exercises the happy path only.
 */
class SsoServiceImplTest {

    private static final String CLIENT_ID = "portfolio";
    private static final String SECRET = "correct-horse-battery-staple";
    private static final String REDIRECT = "https://wekt.in/api/auth/callback";
    private static final String STATE = "opaque-random-state";
    private static final Long USER_ID = 42L;

    private SsoProperties properties;
    private SsoAuthCodeRepository authCodeRepository;
    private UserRepository userRepository;
    private TokenService tokenService;
    private SsoServiceImpl ssoService;

    @BeforeEach
    void setUp() {
        properties = new SsoProperties();
        properties.setClientId(CLIENT_ID);
        properties.setClientSecret(SECRET);
        properties.setRedirectUris(List.of(REDIRECT));
        properties.setRequiredRole("portfolio-admin");

        authCodeRepository = mock(SsoAuthCodeRepository.class);
        userRepository = mock(UserRepository.class);
        tokenService = mock(TokenService.class);

        when(authCodeRepository.save(any(SsoAuthCodeEntity.class)))
            .thenAnswer(invocation -> invocation.getArgument(0));
        when(userRepository.findRolesByUserId(USER_ID)).thenReturn(Set.of("portfolio-admin"));

        ssoService = new SsoServiceImpl(properties, authCodeRepository, userRepository, tokenService);
    }

    // ---------------------------------------------------------------- issueCode

    @Test
    void issueCodeReturnsARedirectCarryingTheCodeAndTheCallersState() {
        String url = ssoService.issueCode(USER_ID, CLIENT_ID, REDIRECT, STATE);

        assertThat(url).startsWith(REDIRECT + "?");
        assertThat(queryParam(url, "state")).isEqualTo(STATE);
        assertThat(queryParam(url, "code")).isNotBlank();
    }

    /**
     * The row must hold a hash, not the code. A database dump is a plausible way to lose this
     * table, and it must not come with usable codes attached — the same rule refresh tokens
     * follow.
     */
    @Test
    void issueCodeStoresOnlyAHashOfTheCode() {
        String url = ssoService.issueCode(USER_ID, CLIENT_ID, REDIRECT, STATE);
        String code = queryParam(url, "code");

        ArgumentCaptor<SsoAuthCodeEntity> saved = ArgumentCaptor.forClass(SsoAuthCodeEntity.class);
        verify(authCodeRepository).save(saved.capture());

        assertThat(saved.getValue().getCodeHash()).isNotEqualTo(code);
        assertThat(saved.getValue().getCodeHash()).isEqualTo(sha256(code));
        assertThat(saved.getValue().isConsumed()).isFalse();
    }

    @Test
    void issueCodeRejectsAnUnregisteredClient() {
        assertThatThrownBy(() -> ssoService.issueCode(USER_ID, "not-a-client", REDIRECT, STATE))
            .isInstanceOf(CustomException.class);
        verify(authCodeRepository, never()).save(any());
    }

    /**
     * Exact string equality, not a prefix. A prefix check on the registered URI would accept
     * this one, and the authorisation code would be delivered to a host the operator never
     * registered — the single most exploited flaw in this kind of flow.
     */
    @Test
    void issueCodeRejectsARedirectUriThatMerelyStartsWithARegisteredOne() {
        assertThatThrownBy(() ->
            ssoService.issueCode(USER_ID, CLIENT_ID, REDIRECT + ".attacker.example", STATE))
            .isInstanceOf(CustomException.class);
        verify(authCodeRepository, never()).save(any());
    }

    @Test
    void issueCodeRejectsAnUnregisteredRedirectUri() {
        assertThatThrownBy(() ->
            ssoService.issueCode(USER_ID, CLIENT_ID, "https://attacker.example/callback", STATE))
            .isInstanceOf(CustomException.class);
        verify(authCodeRepository, never()).save(any());
    }

    /**
     * `state` is the relying party's CSRF defence. Accepting a request without one would let an
     * attacker start a login and hand the victim a callback URL that signs the victim into the
     * attacker's session.
     */
    @Test
    void issueCodeRequiresState() {
        assertThatThrownBy(() -> ssoService.issueCode(USER_ID, CLIENT_ID, REDIRECT, "  "))
            .isInstanceOf(CustomException.class);
        verify(authCodeRepository, never()).save(any());
    }

    /**
     * The check that carries the whole design. Registration is open on the demo, so without it
     * every account that ever signed up could sign in to the relying party.
     */
    @Test
    void issueCodeRejectsAUserWhoLacksTheRoleTheClientRequires() {
        when(userRepository.findRolesByUserId(USER_ID)).thenReturn(Set.of());

        assertThatThrownBy(() -> ssoService.issueCode(USER_ID, CLIENT_ID, REDIRECT, STATE))
            .isInstanceOf(CustomException.class)
            .hasMessageContaining("not permitted");
        verify(authCodeRepository, never()).save(any());
    }

    @Test
    void issueCodeAllowsAnyAuthenticatedUserWhenTheClientRequiresNoRole() {
        properties.setRequiredRole(null);
        when(userRepository.findRolesByUserId(USER_ID)).thenReturn(Set.of());

        assertThat(ssoService.issueCode(USER_ID, CLIENT_ID, REDIRECT, STATE)).contains("code=");
    }

    // ------------------------------------------------------------- exchangeCode

    @Test
    void exchangeCodeIssuesTokensAndMarksTheCodeConsumed() {
        SsoAuthCodeEntity stored = liveCode("the-code");
        when(authCodeRepository.findByCodeHashAndConsumedFalse(sha256("the-code")))
            .thenReturn(Optional.of(stored));
        when(userRepository.findById(USER_ID)).thenReturn(Optional.of(user()));
        when(tokenService.issueTokens(USER_ID, "user@example.com"))
            .thenReturn(new TokenResponse("access", "refresh", 900L));

        TokenResponse response = ssoService.exchangeCode(CLIENT_ID, SECRET, "the-code", REDIRECT);

        assertThat(response.accessToken()).isEqualTo("access");
        assertThat(stored.isConsumed()).isTrue();
        assertThat(stored.getConsumedAt()).isNotNull();
    }

    @Test
    void exchangeCodeRejectsAWrongClientSecret() {
        assertThatThrownBy(() -> ssoService.exchangeCode(CLIENT_ID, "wrong", "the-code", REDIRECT))
            .isInstanceOf(CustomException.class);
        // The code is never even looked up, so a wrong secret cannot be used to probe which
        // codes exist.
        verify(authCodeRepository, never()).findByCodeHashAndConsumedFalse(any());
    }

    @Test
    void exchangeCodeRejectsAnUnknownClientTheSameWayAsABadSecret() {
        assertThatThrownBy(() -> ssoService.exchangeCode("nope", SECRET, "the-code", REDIRECT))
            .isInstanceOf(CustomException.class)
            .hasMessage("client authentication failed");
    }

    @Test
    void exchangeCodeRejectsAnUnknownCode() {
        when(authCodeRepository.findByCodeHashAndConsumedFalse(any())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> ssoService.exchangeCode(CLIENT_ID, SECRET, "nope", REDIRECT))
            .isInstanceOf(CustomException.class);
    }

    @Test
    void exchangeCodeRejectsAnExpiredCode() {
        SsoAuthCodeEntity expired = liveCode("the-code");
        expired.setExpiresAt(Instant.now().minusSeconds(1));
        when(authCodeRepository.findByCodeHashAndConsumedFalse(sha256("the-code")))
            .thenReturn(Optional.of(expired));

        assertThatThrownBy(() -> ssoService.exchangeCode(CLIENT_ID, SECRET, "the-code", REDIRECT))
            .isInstanceOf(CustomException.class);
        verify(tokenService, never()).issueTokens(any(), any());
    }

    /**
     * A code is bound to the client it was minted for. Without this, one registered client could
     * redeem a code issued for another.
     */
    @Test
    void exchangeCodeRejectsACodeMintedForADifferentClient() {
        SsoAuthCodeEntity other = liveCode("the-code");
        other.setClientId("someone-else");
        when(authCodeRepository.findByCodeHashAndConsumedFalse(sha256("the-code")))
            .thenReturn(Optional.of(other));

        assertThatThrownBy(() -> ssoService.exchangeCode(CLIENT_ID, SECRET, "the-code", REDIRECT))
            .isInstanceOf(CustomException.class);
        verify(tokenService, never()).issueTokens(any(), any());
    }

    @Test
    void exchangeCodeRejectsARedirectUriDifferentFromTheOneTheCodeWasIssuedFor() {
        SsoAuthCodeEntity stored = liveCode("the-code");
        when(authCodeRepository.findByCodeHashAndConsumedFalse(sha256("the-code")))
            .thenReturn(Optional.of(stored));

        assertThatThrownBy(() ->
            ssoService.exchangeCode(CLIENT_ID, SECRET, "the-code", "https://wekt.in/elsewhere"))
            .isInstanceOf(CustomException.class);
        verify(tokenService, never()).issueTokens(any(), any());
    }

    /**
     * Every code failure reads the same. Distinct messages would let someone holding a stolen
     * code learn which client it belongs to, or that it existed and was already spent.
     */
    @Test
    void everyCodeFailureCarriesTheSameMessage() {
        SsoAuthCodeEntity wrongClient = liveCode("a");
        wrongClient.setClientId("someone-else");
        SsoAuthCodeEntity expired = liveCode("b");
        expired.setExpiresAt(Instant.now().minusSeconds(1));

        when(authCodeRepository.findByCodeHashAndConsumedFalse(sha256("a")))
            .thenReturn(Optional.of(wrongClient));
        when(authCodeRepository.findByCodeHashAndConsumedFalse(sha256("b")))
            .thenReturn(Optional.of(expired));
        when(authCodeRepository.findByCodeHashAndConsumedFalse(sha256("c")))
            .thenReturn(Optional.empty());

        String expected = catchMessage("a");
        assertThat(expected).isNotBlank();
        assertThat(catchMessage("b")).isEqualTo(expected);
        assertThat(catchMessage("c")).isEqualTo(expected);
        assertThat(catchMessage(null)).isEqualTo(expected);
    }

    // ------------------------------------------------------------------ helpers

    private String catchMessage(String code) {
        try {
            ssoService.exchangeCode(CLIENT_ID, SECRET, code, REDIRECT);
            return "no exception thrown";
        } catch (CustomException e) {
            return e.getMessage();
        }
    }

    private SsoAuthCodeEntity liveCode(String code) {
        return SsoAuthCodeEntity.builder()
            .id(UUID.randomUUID())
            .codeHash(sha256(code))
            .clientId(CLIENT_ID)
            .userId(USER_ID)
            .redirectUri(REDIRECT)
            .expiresAt(Instant.now().plusSeconds(60))
            .consumed(false)
            .build();
    }

    private UserEntity user() {
        UserEntity user = new UserEntity();
        user.setId(USER_ID);
        user.setEmail("user@example.com");
        return user;
    }

    private static String queryParam(String url, String name) {
        for (String pair : URI.create(url).getQuery().split("&")) {
            String[] kv = pair.split("=", 2);
            if (kv[0].equals(name)) {
                return kv.length > 1 ? kv[1] : "";
            }
        }
        return null;
    }

    private static String sha256(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
