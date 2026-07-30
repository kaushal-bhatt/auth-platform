package com.authplatform.auth.service.impl;

import com.authplatform.auth.config.JwtIssuerProperties;
import com.authplatform.auth.dto.TokenResponse;
import com.authplatform.auth.entity.TokenEntity;
import com.authplatform.auth.entity.UserEntity;
import com.authplatform.auth.exception.CustomException;
import com.authplatform.auth.repository.TokenRepository;
import com.authplatform.auth.repository.UserRepository;
import com.authplatform.auth.security.JwtIssuer;
import com.authplatform.auth.service.TokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.HexFormat;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class TokenServiceImpl implements TokenService {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    /**
     * The single message used for every refresh failure that is not an expiry: unknown token,
     * already-revoked token, null/blank input, and a token whose user has since been deleted.
     * Keeping them textually identical means a caller cannot use the response to distinguish
     * "this token never existed" from "this token was already redeemed" from "this account is
     * gone".
     */
    private static final String INVALID_REFRESH_TOKEN = "refresh token is invalid";

    private final TokenRepository tokenRepository;
    private final JwtIssuer jwtIssuer;
    private final JwtIssuerProperties issuerProperties;
    private final UserRepository userRepository;

    /**
     * Mints tokens for a brand-new session. A fresh login is by definition a new session, so a
     * new session id is generated here. The refresh path must NOT come through this overload —
     * see {@link #issueTokensForSession(Long, String, UUID)}.
     */
    @Override
    @Transactional
    public TokenResponse issueTokens(Long userId, String email) {
        return issueTokensForSession(userId, email, UUID.randomUUID());
    }

    /**
     * Mints tokens against an explicit, caller-supplied session id.
     * <p>
     * This exists so that refresh can carry the session id forward. The {@code sess} claim is
     * published to every consumer in the platform as {@code JwtClaims.sessionId}; if it were
     * regenerated on each refresh it would be a per-token identifier rather than a session
     * identifier, changing every 15 minutes with nothing linking the new value to the old. That
     * makes "revoke session X", "log out all devices" and per-session audit trails impossible to
     * build, and {@code session_id} is exactly the column a future refresh-token-reuse family
     * revocation would key on.
     * <p>
     * Deliberately not annotated {@code @Transactional}: it is only ever reached by internal
     * self-invocation from {@link #issueTokens} or {@link #refresh}, both of which are
     * {@code @Transactional} and are entered through the Spring proxy, so this always runs inside
     * their transaction. Annotating it would imply a proxy boundary that self-invocation does not
     * cross.
     */
    TokenResponse issueTokensForSession(Long userId, String email, UUID sessionId) {
        String accessToken = jwtIssuer.issueAccessToken(userId, email, sessionId);
        String refreshToken = generateRefreshToken();

        // createdAt is stamped by TokenEntity's @PrePersist lifecycle callback.
        TokenEntity tokenEntity = TokenEntity.builder()
            .userId(userId)
            .sessionId(sessionId)
            .refreshTokenHash(hash(refreshToken))
            .refreshTokenExpiresAt(Instant.now().plus(issuerProperties.getRefreshTokenExpiryMinutes(), ChronoUnit.MINUTES))
            .revoked(false)
            .build();
        tokenRepository.save(tokenEntity);

        return new TokenResponse(accessToken, refreshToken, jwtIssuer.accessTokenExpirySeconds());
    }

    /**
     * Redeems a refresh token exactly once, rotating it.
     * <p>
     * {@code @Transactional} is required, not merely convenient: the repository lookup takes a
     * {@code PESSIMISTIC_WRITE} row lock ({@code SELECT ... FOR UPDATE}) and a pessimistic lock
     * has no effect — and Spring Data rejects it — outside a transaction. That lock is what makes
     * concurrent redemptions of the same token serialise, so that exactly one wins. See
     * {@link TokenRepository#findByRefreshTokenHashAndRevokedFalse}.
     * <p>
     * Ordering is also deliberate: expiry is checked before the token is honoured, and any
     * failure rolls the whole transaction back — so the OLD refresh token stays usable and a
     * transient fault can never lock a user out of their account.
     */
    @Override
    @Transactional
    public TokenResponse refresh(String refreshToken) {
        // guard before hashing: hash() would NPE on null, surfacing as a 500 with a logged stack
        // trace instead of the uniform 401 that every other invalid-token case produces.
        if (refreshToken == null || refreshToken.isBlank()) {
            throw new CustomException(401, INVALID_REFRESH_TOKEN);
        }

        TokenEntity existing = tokenRepository.findByRefreshTokenHashAndRevokedFalse(hash(refreshToken))
            .orElseThrow(() -> new CustomException(401, INVALID_REFRESH_TOKEN));

        if (existing.getRefreshTokenExpiresAt().isBefore(Instant.now())) {
            throw new CustomException(401, "refresh token has expired");
        }

        existing.setRevoked(true);
        existing.setRevokedAt(Instant.now());
        tokenRepository.save(existing);

        UserEntity user = userRepository.findById(existing.getUserId())
            // same message as an unknown token: a deleted account must not be distinguishable
            // from a bogus refresh token.
            .orElseThrow(() -> new CustomException(401, INVALID_REFRESH_TOKEN));

        // reuse the existing session id - rotation replaces the credential, not the session.
        return issueTokensForSession(user.getId(), user.getEmail(), existing.getSessionId());
    }

    private String generateRefreshToken() {
        byte[] bytes = new byte[32];
        SECURE_RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String hash(String refreshToken) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(refreshToken.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}
