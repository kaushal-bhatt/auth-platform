package com.authplatform.auth.service.impl;

import com.authplatform.auth.config.JwtIssuerProperties;
import com.authplatform.auth.dto.TokenResponse;
import com.authplatform.auth.entity.TokenEntity;
import com.authplatform.auth.entity.UserEntity;
import com.authplatform.auth.exception.CustomException;
import com.authplatform.auth.repository.TokenRepository;
import com.authplatform.auth.repository.UserRepository;
import com.authplatform.auth.security.JwtIssuer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

class TokenServiceImplTest {

    private TokenRepository tokenRepository;
    private UserRepository userRepository;
    private JwtIssuer jwtIssuer;
    private TokenServiceImpl tokenService;

    @BeforeEach
    void setUp() {
        tokenRepository = mock(TokenRepository.class);
        userRepository = mock(UserRepository.class);
        jwtIssuer = mock(JwtIssuer.class);
        when(tokenRepository.save(any(TokenEntity.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(jwtIssuer.issueAccessToken(any(), any(), any())).thenReturn("signed-jwt");
        when(jwtIssuer.accessTokenExpirySeconds()).thenReturn(900L);

        JwtIssuerProperties properties = new JwtIssuerProperties();
        properties.setIssuer("auth-service");
        properties.setAudience("auth-platform-client");
        properties.setAccessTokenExpiryMinutes(15);
        properties.setRefreshTokenExpiryMinutes(43200);

        tokenService = new TokenServiceImpl(tokenRepository, jwtIssuer, properties, userRepository);
    }

    @Test
    void issueTokensReturnsAccessAndRefreshToken() {
        TokenResponse response = tokenService.issueTokens(42L, "user@example.com");

        assertThat(response.accessToken()).isEqualTo("signed-jwt");
        assertThat(response.refreshToken()).isNotBlank();
        assertThat(response.expiresIn()).isEqualTo(900L);
        verify(tokenRepository).save(any(TokenEntity.class));
    }

    @Test
    void refreshRejectsUnknownToken() {
        when(tokenRepository.findByRefreshTokenHashAndRevokedFalse(any())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> tokenService.refresh("garbage-token"))
            .isInstanceOf(CustomException.class)
            .hasMessageContaining("invalid");
    }

    @Test
    void refreshRejectsExpiredToken() {
        TokenEntity expired = TokenEntity.builder()
            .userId(42L)
            .sessionId(UUID.randomUUID())
            .refreshTokenHash("hash")
            .refreshTokenExpiresAt(Instant.now().minusSeconds(60))
            .revoked(false)
            .createdAt(Instant.now())
            .build();
        when(tokenRepository.findByRefreshTokenHashAndRevokedFalse(any())).thenReturn(Optional.of(expired));

        assertThatThrownBy(() -> tokenService.refresh("some-token"))
            .isInstanceOf(CustomException.class)
            .hasMessageContaining("expired");
        // the expiry check must run BEFORE the token is honoured: an expired row is never revoked
        // and never mints anything.
        assertThat(expired.isRevoked()).isFalse();
        verify(tokenRepository, never()).save(any(TokenEntity.class));
    }

    @Test
    void refreshRevokesOldTokenAndIssuesNewOnes() {
        TokenEntity existing = liveToken(42L, UUID.randomUUID());
        when(tokenRepository.findByRefreshTokenHashAndRevokedFalse(any())).thenReturn(Optional.of(existing));
        when(userRepository.findById(42L)).thenReturn(Optional.of(user(42L, "user@example.com")));

        TokenResponse response = tokenService.refresh("some-token");

        assertThat(response.accessToken()).isEqualTo("signed-jwt");
        assertThat(existing.isRevoked()).isTrue();
    }

    // -- additional coverage beyond the brief's four tests -----------------------------

    /**
     * Strengthened: asserting only "not equal to the raw token" would still pass if {@code hash()}
     * returned a fixed constant, or the reversed string, or a truncation. This pins the stored
     * value to the exact SHA-256 hex digest of the refresh token that was handed to the caller —
     * which is also the value {@code refresh()} must recompute to find the row again.
     */
    @Test
    void storedRefreshTokenHashIsTheSha256HexDigestOfTheReturnedRawRefreshToken() {
        ArgumentCaptor<TokenEntity> captor = ArgumentCaptor.forClass(TokenEntity.class);

        TokenResponse response = tokenService.issueTokens(42L, "user@example.com");

        verify(tokenRepository).save(captor.capture());
        String stored = captor.getValue().getRefreshTokenHash();
        // the raw refresh token must never be the value persisted - only its SHA-256 hash is
        // stored, so a database leak alone can never be replayed as a bearer credential.
        assertThat(stored).isNotEqualTo(response.refreshToken());
        assertThat(stored).isEqualTo(sha256Hex(response.refreshToken()));
        assertThat(stored).hasSize(64); // hex-encoded sha-256
        assertThat(stored).matches("[0-9a-f]{64}");
    }

    @Test
    void twoCallsToIssueTokensProduceDifferentRefreshTokens() {
        TokenResponse first = tokenService.issueTokens(42L, "user@example.com");
        TokenResponse second = tokenService.issueTokens(42L, "user@example.com");

        assertThat(first.refreshToken()).isNotEqualTo(second.refreshToken());
    }

    // note: the former `refreshRejectsAlreadyRevokedToken` test lived here. It stubbed
    // findByRefreshTokenHashAndRevokedFalse to return Optional.empty() and asserted "invalid" -
    // byte-for-byte the same stub and assertion as refreshRejectsUnknownToken above. With a mocked
    // repository it could not possibly prove that `revoked=true` excludes a row, because the
    // derived query is never executed. It has been replaced by
    // TokenServiceImplIntegrationTest#aRevokedRowIsNotReturnedByTheDerivedFinder, which runs the
    // real query against a real Postgres.

    /**
     * Fix 7a: a null refresh token used to reach the hashing helper and NPE, surfacing as a 500
     * with a logged stack trace instead of the uniform 401.
     */
    @Test
    void refreshRejectsNullTokenWithTheSameUnauthorizedErrorAsAnInvalidToken() {
        assertThatThrownBy(() -> tokenService.refresh(null))
            .isInstanceOf(CustomException.class)
            .hasMessage("refresh token is invalid");
        verifyNoInteractions(tokenRepository);
    }

    @Test
    void refreshRejectsBlankTokenWithTheSameUnauthorizedErrorAsAnInvalidToken() {
        assertThatThrownBy(() -> tokenService.refresh("   "))
            .isInstanceOf(CustomException.class)
            .hasMessage("refresh token is invalid");
        verifyNoInteractions(tokenRepository);
    }

    /**
     * Fix 7b: a deleted user used to produce "user no longer exists", which is distinguishable
     * from "refresh token is invalid" and therefore leaks account state to anyone holding an old
     * refresh token. Both must be byte-identical.
     */
    @Test
    void refreshReportsAnInvalidTokenRatherThanRevealingThatTheUserWasDeleted() {
        TokenEntity existing = liveToken(42L, UUID.randomUUID());
        when(tokenRepository.findByRefreshTokenHashAndRevokedFalse(any())).thenReturn(Optional.of(existing));
        when(userRepository.findById(42L)).thenReturn(Optional.empty());

        CustomException deletedUser = refreshFailure("some-token");

        when(tokenRepository.findByRefreshTokenHashAndRevokedFalse(any())).thenReturn(Optional.empty());
        CustomException unknownToken = refreshFailure("garbage-token");

        assertThat(deletedUser.getMessage()).isEqualTo(unknownToken.getMessage());
        assertThat(deletedUser.getStatus()).isEqualTo(unknownToken.getStatus());
        assertThat(deletedUser.getMessage()).doesNotContain("user");
    }

    /**
     * Fix 4: the {@code sess} claim is published to every consumer as {@code JwtClaims.sessionId}.
     * Regenerating it on each refresh would make it a per-token id that changes every 15 minutes
     * with nothing linking old to new, which makes "log out all devices" and per-session audit
     * impossible. Both the new token's claim and the new row's {@code session_id} must reuse the
     * redeemed row's value.
     */
    @Test
    void refreshCarriesTheExistingSessionIdForwardIntoTheNewTokenAndTheNewRow() {
        UUID existingSessionId = UUID.randomUUID();
        TokenEntity existing = liveToken(42L, existingSessionId);
        when(tokenRepository.findByRefreshTokenHashAndRevokedFalse(any())).thenReturn(Optional.of(existing));
        when(userRepository.findById(42L)).thenReturn(Optional.of(user(42L, "user@example.com")));

        tokenService.refresh("some-token");

        verify(jwtIssuer).issueAccessToken(eq(42L), eq("user@example.com"), eq(existingSessionId));

        ArgumentCaptor<TokenEntity> captor = ArgumentCaptor.forClass(TokenEntity.class);
        verify(tokenRepository, times(2)).save(captor.capture());
        List<TokenEntity> saved = captor.getAllValues();
        // first save is the revocation of the redeemed row, second is the freshly minted row
        assertThat(saved.get(0)).isSameAs(existing);
        assertThat(saved.get(1).getSessionId()).isEqualTo(existingSessionId);
        assertThat(saved.get(1).getRefreshTokenHash()).isNotEqualTo(existing.getRefreshTokenHash());
    }

    /**
     * The other half of Fix 4: rotation reuses a session, but a fresh login must start a new one -
     * so the public two-argument {@code issueTokens} must keep minting a brand-new session id.
     */
    @Test
    void twoIndependentLoginsGetDifferentSessionIds() {
        ArgumentCaptor<UUID> claimCaptor = ArgumentCaptor.forClass(UUID.class);
        ArgumentCaptor<TokenEntity> rowCaptor = ArgumentCaptor.forClass(TokenEntity.class);

        tokenService.issueTokens(42L, "user@example.com");
        tokenService.issueTokens(42L, "user@example.com");

        verify(jwtIssuer, times(2)).issueAccessToken(any(), any(), claimCaptor.capture());
        verify(tokenRepository, times(2)).save(rowCaptor.capture());

        assertThat(claimCaptor.getAllValues().get(0)).isNotEqualTo(claimCaptor.getAllValues().get(1));
        assertThat(rowCaptor.getAllValues().get(0).getSessionId())
            .isNotEqualTo(rowCaptor.getAllValues().get(1).getSessionId());
        // the claim and the persisted row must agree, per login
        assertThat(rowCaptor.getAllValues().get(0).getSessionId()).isEqualTo(claimCaptor.getAllValues().get(0));
        assertThat(rowCaptor.getAllValues().get(1).getSessionId()).isEqualTo(claimCaptor.getAllValues().get(1));
    }

    /**
     * Fix 7c: the revocation instant must be stamped, not left null, so a token-theft
     * investigation can order the revocations across a session's token chain.
     */
    @Test
    void refreshStampsTheRevocationInstantOnTheRedeemedRow() {
        TokenEntity existing = liveToken(42L, UUID.randomUUID());
        assertThat(existing.getRevokedAt()).isNull();
        when(tokenRepository.findByRefreshTokenHashAndRevokedFalse(any())).thenReturn(Optional.of(existing));
        when(userRepository.findById(42L)).thenReturn(Optional.of(user(42L, "user@example.com")));

        Instant before = Instant.now();
        tokenService.refresh("some-token");

        assertThat(existing.isRevoked()).isTrue();
        assertThat(existing.getRevokedAt()).isNotNull();
        assertThat(existing.getRevokedAt()).isAfterOrEqualTo(before);
    }

    /** Invokes refresh expecting it to fail, returning the exception so its fields can be compared. */
    private CustomException refreshFailure(String refreshToken) {
        try {
            tokenService.refresh(refreshToken);
            return fail("expected refresh to throw CustomException");
        } catch (CustomException e) {
            return e;
        }
    }

    private static TokenEntity liveToken(Long userId, UUID sessionId) {
        return TokenEntity.builder()
            .userId(userId)
            .sessionId(sessionId)
            .refreshTokenHash("hash")
            .refreshTokenExpiresAt(Instant.now().plusSeconds(600))
            .revoked(false)
            .createdAt(Instant.now())
            .build();
    }

    private static UserEntity user(Long id, String email) {
        return UserEntity.builder()
            .id(id)
            .email(email)
            .passwordHash("hash")
            .createdAt(Instant.now())
            .updatedAt(Instant.now())
            .build();
    }

    private static String sha256Hex(String value) {
        try {
            return HexFormat.of().formatHex(
                MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
