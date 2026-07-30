package com.authplatform.jwt.service.impl;

import com.authplatform.jwt.config.JwtLibProperties;
import com.authplatform.jwt.model.JwtClaims;
import com.authplatform.jwt.model.JwtVerificationResult;
import com.authplatform.jwt.service.JwksClient;
import com.authplatform.jwt.service.JwtVerificationService;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.text.ParseException;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

@Slf4j
@RequiredArgsConstructor
public class JwtVerificationServiceImpl implements JwtVerificationService {

    /**
     * upper bound on the length of an attacker controlled value echoed into a failure message,
     * so a consumer that logs the message cannot be flooded from a single token.
     */
    private static final int MAX_ECHOED_VALUE_LENGTH = 64;

    private final JwksClient jwksClient;
    private final JwtLibProperties properties;

    @Override
    public JwtVerificationResult verify(String token) {
        try {
            return doVerify(token);
        } catch (Exception e) {
            log.error("unexpected error while verifying jwt token", e);
            return JwtVerificationResult.failure("unexpected error during jwt verification");
        }
    }

    private JwtVerificationResult doVerify(String token) {
        // unauthenticated traffic must not be able to write log lines; reject quietly
        if (token == null || token.isBlank()) {
            return JwtVerificationResult.failure("missing jwt token");
        }

        String expectedIssuer = properties.getExpectedIssuer();
        if (expectedIssuer == null || expectedIssuer.isBlank()) {
            log.error("jwt verification is misconfigured: expected issuer is not set");
            return JwtVerificationResult.failure("jwt verification is misconfigured: expected issuer is not set");
        }

        SignedJWT signedJWT;
        try {
            signedJWT = SignedJWT.parse(token);
        } catch (ParseException e) {
            return JwtVerificationResult.failure("invalid jwt token format");
        }

        // rfc 8725 section 3.1: confirm the algorithm explicitly rather than inheriting
        // whatever set the verifier implementation happens to accept
        JWSAlgorithm algorithm = signedJWT.getHeader().getAlgorithm();
        if (!JWSAlgorithm.RS256.equals(algorithm)) {
            return JwtVerificationResult.failure(
                "unsupported jwt signing algorithm: " + sanitizeForMessage(String.valueOf(algorithm)));
        }

        String keyId = signedJWT.getHeader().getKeyID();
        if (keyId == null) {
            return JwtVerificationResult.failure("missing key id in jwt header");
        }

        Optional<RSAKey> keyOpt = jwksClient.getKey(keyId);
        if (keyOpt.isEmpty()) {
            return JwtVerificationResult.failure("public key not found for key id: " + sanitizeForMessage(keyId));
        }

        try {
            if (!signedJWT.verify(new RSASSAVerifier(keyOpt.get()))) {
                return JwtVerificationResult.failure("invalid jwt signature");
            }
        } catch (JOSEException e) {
            return JwtVerificationResult.failure("signature verification failed: " + e.getMessage());
        }

        JWTClaimsSet claimsSet;
        try {
            claimsSet = signedJWT.getJWTClaimsSet();
        } catch (ParseException e) {
            return JwtVerificationResult.failure("failed to parse jwt claims");
        }

        if (claimsSet.getExpirationTime() == null) {
            return JwtVerificationResult.failure("missing expiry time in jwt");
        }
        if (claimsSet.getExpirationTime().toInstant().isBefore(Instant.now())) {
            return JwtVerificationResult.failure("jwt token has expired");
        }
        // rfc 8725: nbf is optional, but must be honoured when present
        if (claimsSet.getNotBeforeTime() != null
            && claimsSet.getNotBeforeTime().toInstant().isAfter(Instant.now())) {
            return JwtVerificationResult.failure("jwt token is not yet valid");
        }
        if (claimsSet.getIssuer() == null || !expectedIssuer.equals(claimsSet.getIssuer())) {
            return JwtVerificationResult.failure(
                "invalid issuer: " + sanitizeForMessage(String.valueOf(claimsSet.getIssuer())));
        }
        if (claimsSet.getSubject() == null) {
            return JwtVerificationResult.failure("missing subject in jwt");
        }
        // rfc 8725 section 3.9: optional, only enforced when an expected audience is configured
        if (!audienceAccepted(claimsSet.getAudience())) {
            return JwtVerificationResult.failure("jwt audience does not contain the expected audience");
        }

        return JwtVerificationResult.success(toClaims(claimsSet));
    }

    @Override
    public JwtClaims extractClaimsWithoutVerification(String token) {
        if (token == null || token.isBlank()) {
            throw new IllegalArgumentException("jwt token must not be null or blank");
        }
        try {
            return toClaims(SignedJWT.parse(token).getJWTClaimsSet());
        } catch (ParseException | RuntimeException e) {
            throw new IllegalArgumentException("failed to extract jwt claims", e);
        }
    }

    private boolean audienceAccepted(List<String> tokenAudience) {
        String expectedAudience = properties.getExpectedAudience();
        if (expectedAudience == null || expectedAudience.isBlank()) {
            return true;
        }
        return tokenAudience != null && tokenAudience.contains(expectedAudience);
    }

    /**
     * removes cr/lf and caps the length of an attacker controlled value before it is embedded
     * in a failure message, so a consumer that logs the message unescaped cannot be tricked
     * into forging log entries. only the message text is sanitised - the value used for the
     * actual key lookup is always the untouched original. a null input yields an empty string
     * rather than throwing, so a future call site that passes a nullable value fails safe.
     */
    private static String sanitizeForMessage(String value) {
        if (value == null) {
            return "";
        }
        String singleLine = value.replace("\r", "").replace("\n", "");
        return singleLine.length() > MAX_ECHOED_VALUE_LENGTH
            ? singleLine.substring(0, MAX_ECHOED_VALUE_LENGTH)
            : singleLine;
    }

    private JwtClaims toClaims(JWTClaimsSet claimsSet) {
        String audience = (claimsSet.getAudience() != null && !claimsSet.getAudience().isEmpty())
            ? claimsSet.getAudience().get(0)
            : null;
        return new JwtClaims(
            claimsSet.getSubject(),
            (String) claimsSet.getClaim("email"),
            claimsSet.getIssuer(),
            audience,
            (String) claimsSet.getClaim("sess"),
            claimsSet.getIssueTime() != null ? claimsSet.getIssueTime().toInstant() : null,
            claimsSet.getExpirationTime() != null ? claimsSet.getExpirationTime().toInstant() : null
        );
    }
}
