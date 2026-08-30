package com.authplatform.auth.service.impl;

import com.authplatform.auth.config.SsoProperties;
import com.authplatform.auth.dto.TokenResponse;
import com.authplatform.auth.entity.SsoAuthCodeEntity;
import com.authplatform.auth.entity.UserEntity;
import com.authplatform.auth.exception.CustomException;
import com.authplatform.auth.repository.SsoAuthCodeRepository;
import com.authplatform.auth.repository.UserRepository;
import com.authplatform.auth.service.SsoService;
import com.authplatform.auth.service.TokenService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.HexFormat;

@Slf4j
@Service
@RequiredArgsConstructor
public class SsoServiceImpl implements SsoService {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    /**
     * The single message for every code failure that is not a client-authentication failure:
     * unknown code, expired code, already-redeemed code, a code minted for a different client,
     * and one minted for a different redirect URI.
     * <p>
     * Textually identical on purpose. Distinct messages would let a caller holding a stolen code
     * probe which client it belongs to, or learn that a code existed and was already spent —
     * neither of which they have any business finding out. {@code TokenServiceImpl} keeps its
     * refresh-token failures uniform for the same reason.
     */
    private static final String INVALID_CODE = "authorization code is invalid";

    private final SsoProperties ssoProperties;
    private final SsoAuthCodeRepository authCodeRepository;
    private final UserRepository userRepository;
    private final TokenService tokenService;

    @Override
    public void validateAuthorizeRequest(String clientId, String redirectUri) {
        requireRegistered(clientId, redirectUri);
    }

    @Override
    @Transactional
    public String issueCode(Long userId, String clientId, String redirectUri, String state) {
        // `state` is the relying party's CSRF defence: it generates a random value, sends it
        // here, and refuses the callback if what comes back does not match. Required rather than
        // optional because an optional security parameter is one that eventually gets left out —
        // and without it an attacker can start their own login and hand the victim a callback
        // URL that signs the victim into the attacker's session.
        if (state == null || state.isBlank()) {
            throw new CustomException(400, "state is required");
        }

        SsoProperties.Client client = requireRegistered(clientId, redirectUri);

        String requiredRole = client.getRequiredRole();
        if (requiredRole != null && !requiredRole.isBlank()
            && !userRepository.findRolesByUserId(userId).contains(requiredRole)) {
            // Registration on the demo is open to anyone, so "holds a valid token" is not a
            // reason to let someone into another site. This is the check that makes the
            // difference.
            log.info("sso: user {} lacks role {} required by client {}", userId, requiredRole, clientId);
            throw new CustomException(403, "this account is not permitted to sign in to that application");
        }

        // Bounded housekeeping instead of a scheduled job: codes live for a minute, and rows
        // would otherwise accumulate for the life of the deployment. Running it here ties the
        // work to actual logins, which are rare, rather than adding a scheduler for one table.
        authCodeRepository.deleteExpiredBefore(
            Instant.now().minus(ssoProperties.getCodeRetentionMinutes(), ChronoUnit.MINUTES));

        String code = randomToken();
        authCodeRepository.save(SsoAuthCodeEntity.builder()
            .codeHash(sha256(code))
            .clientId(clientId)
            .userId(userId)
            .redirectUri(redirectUri)
            .expiresAt(Instant.now().plusSeconds(ssoProperties.getCodeTtlSeconds()))
            .consumed(false)
            .build());

        String separator = redirectUri.contains("?") ? "&" : "?";
        return redirectUri + separator
            + "code=" + URLEncoder.encode(code, StandardCharsets.UTF_8)
            + "&state=" + URLEncoder.encode(state, StandardCharsets.UTF_8);
    }

    /**
     * {@code @Transactional} is required, not decorative: the lookup takes a
     * {@code PESSIMISTIC_WRITE} row lock, which has no effect outside a transaction and which
     * Spring Data refuses to apply without one. That lock is the whole of "single use" — see
     * {@link SsoAuthCodeRepository#findByCodeHashAndConsumedFalse}.
     */
    @Override
    @Transactional
    public TokenResponse exchangeCode(String clientId, String clientSecret, String code, String redirectUri) {
        SsoProperties.Client client = ssoProperties.getClients().get(clientId);
        if (client == null || !secretMatches(client.getSecret(), clientSecret)) {
            // Same response whether the client is unknown or the secret is wrong, so this cannot
            // be used to enumerate registered clients.
            throw new CustomException(401, "client authentication failed");
        }

        if (code == null || code.isBlank()) {
            // Guard before hashing: sha256(null) would throw and surface as a 500 with a stack
            // trace instead of the uniform rejection every other bad code produces.
            throw new CustomException(400, INVALID_CODE);
        }

        SsoAuthCodeEntity authCode = authCodeRepository.findByCodeHashAndConsumedFalse(sha256(code))
            .orElseThrow(() -> new CustomException(400, INVALID_CODE));

        // Bound to the client it was minted for: a code leaked to another registered client must
        // not be redeemable by it.
        if (!authCode.getClientId().equals(clientId)) {
            throw new CustomException(400, INVALID_CODE);
        }
        // And to the exact redirect URI: without this, a code obtained for one registered URI
        // could be redeemed while claiming another.
        if (!authCode.getRedirectUri().equals(redirectUri)) {
            throw new CustomException(400, INVALID_CODE);
        }
        if (authCode.getExpiresAt().isBefore(Instant.now())) {
            throw new CustomException(400, INVALID_CODE);
        }

        authCode.setConsumed(true);
        authCode.setConsumedAt(Instant.now());
        authCodeRepository.save(authCode);

        UserEntity user = userRepository.findById(authCode.getUserId())
            // A deleted account must not be distinguishable from a bogus code.
            .orElseThrow(() -> new CustomException(400, INVALID_CODE));

        return tokenService.issueTokens(user.getId(), user.getEmail());
    }

    private SsoProperties.Client requireRegistered(String clientId, String redirectUri) {
        SsoProperties.Client client = ssoProperties.getClients().get(clientId);
        if (client == null) {
            throw new CustomException(400, "unknown client");
        }
        // Full string equality, never a prefix or host comparison. A prefix match on
        // "https://wekt.in/" accepts "https://wekt.in/@attacker.example"; a host match ignores
        // the path entirely. Either turns this endpoint into an open redirect that hands
        // authorisation codes to whoever asks — the most exploited flaw in this kind of flow.
        if (redirectUri == null || !client.getRedirectUris().contains(redirectUri)) {
            throw new CustomException(400, "redirect_uri is not registered for this client");
        }
        return client;
    }

    /**
     * Constant-time comparison. {@code String.equals} returns as soon as two bytes differ, so
     * the time it takes leaks how much of a guess was correct — enough, over many attempts, to
     * recover a secret one character at a time.
     */
    private boolean secretMatches(String configured, String presented) {
        if (configured == null || presented == null) {
            return false;
        }
        return MessageDigest.isEqual(
            configured.getBytes(StandardCharsets.UTF_8),
            presented.getBytes(StandardCharsets.UTF_8));
    }

    private String randomToken() {
        byte[] bytes = new byte[32];
        SECURE_RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String sha256(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}
