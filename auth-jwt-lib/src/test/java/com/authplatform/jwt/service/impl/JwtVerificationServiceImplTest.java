package com.authplatform.jwt.service.impl;

import com.authplatform.jwt.config.JwtLibProperties;
import com.authplatform.jwt.model.JwtClaims;
import com.authplatform.jwt.model.JwtVerificationResult;
import com.authplatform.jwt.service.JwksClient;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class JwtVerificationServiceImplTest {

    private static final String KEY_ID = "key-1";

    private RSAKey signingKey;
    /** a second, unrelated keypair standing in for an attacker who does not hold the real key. */
    private RSAKey attackerKey;
    private JwksClient jwksClient;
    private JwtLibProperties properties;
    private JwtVerificationServiceImpl service;

    @BeforeEach
    void setUp() throws Exception {
        signingKey = generateKey(KEY_ID);
        attackerKey = generateKey(KEY_ID);
        RSAKey publicKey = signingKey.toPublicJWK();

        jwksClient = mock(JwksClient.class);
        when(jwksClient.getKey(KEY_ID)).thenReturn(Optional.of(publicKey));

        properties = new JwtLibProperties();
        properties.setExpectedIssuer("auth-service");
        service = new JwtVerificationServiceImpl(jwksClient, properties);
    }

    private static RSAKey generateKey(String keyId) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();
        return new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
            .privateKey((RSAPrivateKey) keyPair.getPrivate())
            .keyID(keyId)
            .keyUse(KeyUse.SIGNATURE)
            .build();
    }

    private JWTClaimsSet.Builder validClaims() {
        return new JWTClaimsSet.Builder()
            .subject("42")
            .issuer("auth-service")
            .audience("web-client")
            .claim("email", "a@b.com")
            .claim("sess", "sess-1")
            .issueTime(new Date())
            .expirationTime(Date.from(Instant.now().plusSeconds(300)));
    }

    private static JWSHeader rs256Header() {
        return new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(KEY_ID).build();
    }

    private static String sign(RSAKey key, JWSHeader header, JWTClaimsSet claims) throws JOSEException {
        SignedJWT signedJWT = new SignedJWT(header, claims);
        signedJWT.sign(new RSASSASigner(key));
        return signedJWT.serialize();
    }

    private String signToken(Instant expiry, String issuer) throws JOSEException {
        return sign(signingKey, rs256Header(), validClaims()
            .issuer(issuer)
            .expirationTime(Date.from(expiry))
            .build());
    }

    // ---------------------------------------------------------------- happy path

    @Test
    void verifyReturnsSuccessForValidToken() throws Exception {
        String token = signToken(Instant.now().plusSeconds(300), "auth-service");

        JwtVerificationResult result = service.verify(token);

        assertThat(result.valid()).isTrue();
        assertThat(result.claims().userId()).isEqualTo("42");
        assertThat(result.claims().email()).isEqualTo("a@b.com");
    }

    // ------------------------------------------- signature and algorithm integrity

    @Test
    void verifyFailsForTokenSignedByADifferentRsaKey() throws Exception {
        // same kid in the header, but signed with a key the jwks endpoint never published
        String token = sign(attackerKey, rs256Header(), validClaims().build());

        JwtVerificationResult result = service.verify(token);

        assertThat(result.valid()).isFalse();
        assertThat(result.claims()).isNull();
        assertThat(result.errorMessage()).isEqualTo("invalid jwt signature");
    }

    @Test
    void verifyFailsForTamperedPayloadWithOriginalSignatureReattached() throws Exception {
        SignedJWT original = SignedJWT.parse(sign(signingKey, rs256Header(), validClaims().build()));
        JWTClaimsSet tamperedClaims = new JWTClaimsSet.Builder(original.getJWTClaimsSet())
            .subject("999")
            .build();
        SignedJWT tampered = new SignedJWT(
            original.getParsedParts()[0],
            tamperedClaims.toPayload().toBase64URL(),
            original.getSignature());

        JwtVerificationResult result = service.verify(tampered.serialize());

        assertThat(result.valid()).isFalse();
        assertThat(result.claims()).isNull();
        assertThat(result.errorMessage()).isEqualTo("invalid jwt signature");
    }

    @Test
    void verifyFailsForHs256TokenMacedWithTheRsaPublicKeyBytes() throws Exception {
        // classic alg confusion attempt: the "secret" is the public key everyone can read
        byte[] publicKeyBytes = signingKey.toRSAPublicKey().getEncoded();
        SignedJWT signedJWT = new SignedJWT(
            new JWSHeader.Builder(JWSAlgorithm.HS256).keyID(KEY_ID).build(),
            validClaims().build());
        signedJWT.sign(new MACSigner(publicKeyBytes));

        JwtVerificationResult result = service.verify(signedJWT.serialize());

        assertThat(result.valid()).isFalse();
        assertThat(result.claims()).isNull();
        assertThat(result.errorMessage()).isEqualTo("unsupported jwt signing algorithm: HS256");
    }

    @Test
    void verifyFailsForUnsignedAlgNoneToken() {
        String token = new PlainJWT(validClaims().build()).serialize();

        JwtVerificationResult result = service.verify(token);

        assertThat(result.valid()).isFalse();
        assertThat(result.claims()).isNull();
        assertThat(result.errorMessage()).isEqualTo("invalid jwt token format");
    }

    @Test
    void verifyFailsForRs512SignedToken() throws Exception {
        String token = sign(signingKey,
            new JWSHeader.Builder(JWSAlgorithm.RS512).keyID(KEY_ID).build(),
            validClaims().build());

        JwtVerificationResult result = service.verify(token);

        assertThat(result.valid()).isFalse();
        assertThat(result.claims()).isNull();
        assertThat(result.errorMessage()).isEqualTo("unsupported jwt signing algorithm: RS512");
    }

    // ------------------------------------------------------------ key resolution

    @Test
    void verifyFailsWhenKeyIdMissingFromHeader() throws Exception {
        String token = sign(signingKey,
            new JWSHeader.Builder(JWSAlgorithm.RS256).build(),
            validClaims().build());

        JwtVerificationResult result = service.verify(token);

        assertThat(result.valid()).isFalse();
        assertThat(result.errorMessage()).isEqualTo("missing key id in jwt header");
    }

    @Test
    void verifyFailsWhenKeyIdNotPresentInJwks() throws Exception {
        when(jwksClient.getKey("unknown-key")).thenReturn(Optional.empty());
        String token = sign(signingKey,
            new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("unknown-key").build(),
            validClaims().build());

        JwtVerificationResult result = service.verify(token);

        assertThat(result.valid()).isFalse();
        assertThat(result.errorMessage()).isEqualTo("public key not found for key id: unknown-key");
    }

    @Test
    void verifyStripsNewlinesAndTruncatesKeyIdEchoedIntoFailureMessage() throws Exception {
        String maliciousKeyId = "abc\r\ninjected log line" + "x".repeat(200);
        when(jwksClient.getKey(maliciousKeyId)).thenReturn(Optional.empty());
        String token = sign(signingKey,
            new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(maliciousKeyId).build(),
            validClaims().build());

        JwtVerificationResult result = service.verify(token);

        assertThat(result.valid()).isFalse();
        assertThat(result.errorMessage()).doesNotContain("\r").doesNotContain("\n");
        assertThat(result.errorMessage()).startsWith("public key not found for key id: abcinjected log line");
        assertThat(result.errorMessage()).hasSize("public key not found for key id: ".length() + 64);
    }

    // ---------------------------------------------------------- claim validation

    @Test
    void verifyFailsForExpiredToken() throws Exception {
        String token = signToken(Instant.now().minusSeconds(60), "auth-service");

        JwtVerificationResult result = service.verify(token);

        assertThat(result.valid()).isFalse();
        assertThat(result.errorMessage()).contains("expired");
    }

    @Test
    void verifyFailsWhenExpiryMissing() throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
            .subject("42")
            .issuer("auth-service")
            .build();
        String token = sign(signingKey, rs256Header(), claims);

        JwtVerificationResult result = service.verify(token);

        assertThat(result.valid()).isFalse();
        assertThat(result.errorMessage()).isEqualTo("missing expiry time in jwt");
    }

    @Test
    void verifyFailsWhenSubjectMissing() throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
            .issuer("auth-service")
            .expirationTime(Date.from(Instant.now().plusSeconds(300)))
            .build();
        String token = sign(signingKey, rs256Header(), claims);

        JwtVerificationResult result = service.verify(token);

        assertThat(result.valid()).isFalse();
        assertThat(result.errorMessage()).isEqualTo("missing subject in jwt");
    }

    @Test
    void verifyFailsForWrongIssuer() throws Exception {
        String token = signToken(Instant.now().plusSeconds(300), "someone-else");

        JwtVerificationResult result = service.verify(token);

        assertThat(result.valid()).isFalse();
        assertThat(result.errorMessage()).contains("invalid issuer");
    }

    @Test
    void verifyFailsWhenIssuerMissing() throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
            .subject("42")
            .expirationTime(Date.from(Instant.now().plusSeconds(300)))
            .build();
        String token = sign(signingKey, rs256Header(), claims);

        JwtVerificationResult result = service.verify(token);

        assertThat(result.valid()).isFalse();
        assertThat(result.errorMessage()).contains("invalid issuer");
    }

    @Test
    void verifyFailsWhenNotBeforeIsInTheFuture() throws Exception {
        String token = sign(signingKey, rs256Header(), validClaims()
            .notBeforeTime(Date.from(Instant.now().plusSeconds(3600)))
            .build());

        JwtVerificationResult result = service.verify(token);

        assertThat(result.valid()).isFalse();
        assertThat(result.errorMessage()).isEqualTo("jwt token is not yet valid");
    }

    @Test
    void verifySucceedsWhenNotBeforeIsInThePast() throws Exception {
        String token = sign(signingKey, rs256Header(), validClaims()
            .notBeforeTime(Date.from(Instant.now().minusSeconds(3600)))
            .build());

        JwtVerificationResult result = service.verify(token);

        assertThat(result.valid()).isTrue();
        assertThat(result.claims().userId()).isEqualTo("42");
    }

    // -------------------------------------------------------- audience validation

    @Test
    void verifySucceedsWhenExpectedAudienceMatches() throws Exception {
        properties.setExpectedAudience("web-client");
        String token = signToken(Instant.now().plusSeconds(300), "auth-service");

        JwtVerificationResult result = service.verify(token);

        assertThat(result.valid()).isTrue();
        assertThat(result.claims().audience()).isEqualTo("web-client");
    }

    @Test
    void verifyFailsWhenExpectedAudienceDoesNotMatch() throws Exception {
        properties.setExpectedAudience("mobile-client");
        String token = signToken(Instant.now().plusSeconds(300), "auth-service");

        JwtVerificationResult result = service.verify(token);

        assertThat(result.valid()).isFalse();
        assertThat(result.claims()).isNull();
        assertThat(result.errorMessage()).isEqualTo("jwt audience does not contain the expected audience");
    }

    @Test
    void verifyFailsWhenExpectedAudienceConfiguredButTokenHasNoAudienceClaimAtAll() throws Exception {
        // nimbus's JWTClaimsSet#getAudience() returns an EMPTY LIST (never null) when the aud
        // claim is absent altogether. this pins that an expected audience must still reject a
        // token that never carried an audience, so a future refactor cannot introduce
        // "if (audience.isEmpty()) return true;" and silently open a hole.
        properties.setExpectedAudience("web-client");
        JWTClaimsSet claimsWithNoAudience = new JWTClaimsSet.Builder()
            .subject("42")
            .issuer("auth-service")
            .claim("email", "a@b.com")
            .claim("sess", "sess-1")
            .issueTime(new Date())
            .expirationTime(Date.from(Instant.now().plusSeconds(300)))
            .build();
        assertThat(claimsWithNoAudience.getAudience()).isNotNull().isEmpty();
        String token = sign(signingKey, rs256Header(), claimsWithNoAudience);

        JwtVerificationResult result = service.verify(token);

        assertThat(result.valid()).isFalse();
        assertThat(result.claims()).isNull();
        assertThat(result.errorMessage()).isEqualTo("jwt audience does not contain the expected audience");
    }

    @Test
    void verifySucceedsWhenMultiValuedAudienceContainsExpectedAudience() throws Exception {
        properties.setExpectedAudience("web-client");
        String token = sign(signingKey, rs256Header(), validClaims()
            .audience(List.of("other-client", "web-client"))
            .build());

        JwtVerificationResult result = service.verify(token);

        assertThat(result.valid()).isTrue();
        assertThat(result.claims()).isNotNull();
        assertThat(result.claims().userId()).isEqualTo("42");
    }

    @Test
    void verifyDoesNotEnforceAudienceWhenExpectedAudienceNotSet() throws Exception {
        assertThat(properties.getExpectedAudience()).isNull();
        String token = sign(signingKey, rs256Header(), validClaims()
            .audience("some-other-client")
            .build());

        JwtVerificationResult result = service.verify(token);

        assertThat(result.valid()).isTrue();
        assertThat(result.claims().audience()).isEqualTo("some-other-client");
    }

    // ------------------------------------------------------------ misconfiguration

    @Test
    void verifyFailsClosedWithMisconfigurationMessageWhenExpectedIssuerNotSet() throws Exception {
        String token = signToken(Instant.now().plusSeconds(300), "auth-service");
        JwtLibProperties unconfigured = new JwtLibProperties();
        JwtVerificationServiceImpl misconfiguredService =
            new JwtVerificationServiceImpl(jwksClient, unconfigured);

        JwtVerificationResult result = misconfiguredService.verify(token);

        assertThat(result.valid()).isFalse();
        assertThat(result.claims()).isNull();
        assertThat(result.errorMessage())
            .isEqualTo("jwt verification is misconfigured: expected issuer is not set");
    }

    @Test
    void verifyFailsClosedWhenExpectedIssuerIsBlank() throws Exception {
        String token = signToken(Instant.now().plusSeconds(300), "auth-service");
        JwtLibProperties blankIssuer = new JwtLibProperties();
        blankIssuer.setExpectedIssuer("   ");
        JwtVerificationServiceImpl misconfiguredService =
            new JwtVerificationServiceImpl(jwksClient, blankIssuer);

        JwtVerificationResult result = misconfiguredService.verify(token);

        assertThat(result.valid()).isFalse();
        assertThat(result.errorMessage())
            .isEqualTo("jwt verification is misconfigured: expected issuer is not set");
    }

    // --------------------------------------------------------------- input handling

    @Test
    void verifyFailsForNullToken() {
        JwtVerificationResult result = service.verify(null);

        assertThat(result.valid()).isFalse();
        assertThat(result.claims()).isNull();
        assertThat(result.errorMessage()).isEqualTo("missing jwt token");
    }

    @Test
    void verifyFailsForEmptyToken() {
        JwtVerificationResult result = service.verify("");

        assertThat(result.valid()).isFalse();
        assertThat(result.errorMessage()).isEqualTo("missing jwt token");
    }

    @Test
    void verifyFailsForWhitespaceOnlyToken() {
        JwtVerificationResult result = service.verify("   ");

        assertThat(result.valid()).isFalse();
        assertThat(result.errorMessage()).isEqualTo("missing jwt token");
    }

    @Test
    void verifyReturnsFailureWhenJwksClientThrows() throws Exception {
        String token = signToken(Instant.now().plusSeconds(300), "auth-service");

        JwksClient throwingJwksClient = mock(JwksClient.class);
        when(throwingJwksClient.getKey(KEY_ID)).thenThrow(new RuntimeException("jwks endpoint unreachable"));

        JwtLibProperties props = new JwtLibProperties();
        props.setExpectedIssuer("auth-service");
        JwtVerificationServiceImpl serviceWithThrowingClient = new JwtVerificationServiceImpl(throwingJwksClient, props);

        JwtVerificationResult result = serviceWithThrowingClient.verify(token);

        assertThat(result.valid()).isFalse();
        assertThat(result.claims()).isNull();
        assertThat(result.errorMessage()).isEqualTo("unexpected error during jwt verification");
    }

    // ------------------------------------- extractClaimsWithoutVerification semantics

    @Test
    void extractClaimsWithoutVerificationReturnsClaimsForAttackerSignedToken() throws Exception {
        // DELIBERATE: this documents the dangerous contract of the method in executable form.
        // The token below is signed with a key the jwks endpoint never published, so verify()
        // rejects it - yet extractClaimsWithoutVerification still hands back a fully populated
        // userId. That is exactly why the method must never drive an authorization decision.
        String attackerToken = sign(attackerKey, rs256Header(), validClaims().subject("999").build());
        assertThat(service.verify(attackerToken).valid()).isFalse();

        JwtClaims claims = service.extractClaimsWithoutVerification(attackerToken);

        assertThat(claims.userId()).isEqualTo("999");
        assertThat(claims.email()).isEqualTo("a@b.com");
        assertThat(claims.issuer()).isEqualTo("auth-service");
    }

    @Test
    void extractClaimsWithoutVerificationThrowsIllegalArgumentForMalformedToken() {
        assertThatThrownBy(() -> service.extractClaimsWithoutVerification("not-a-jwt"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessage("failed to extract jwt claims")
            .hasCauseInstanceOf(Exception.class);
    }

    @Test
    void extractClaimsWithoutVerificationThrowsIllegalArgumentForNullToken() {
        assertThatThrownBy(() -> service.extractClaimsWithoutVerification(null))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessage("jwt token must not be null or blank");
    }

    @Test
    void extractClaimsWithoutVerificationThrowsIllegalArgumentForBlankToken() {
        assertThatThrownBy(() -> service.extractClaimsWithoutVerification("   "))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessage("jwt token must not be null or blank");
    }

    @Test
    void extractClaimsWithoutVerificationThrowsIllegalArgumentWhenEmailClaimIsANumber() throws Exception {
        String token = sign(signingKey, rs256Header(), validClaims()
            .claim("email", 12345)
            .build());

        assertThatThrownBy(() -> service.extractClaimsWithoutVerification(token))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessage("failed to extract jwt claims")
            .hasCauseInstanceOf(ClassCastException.class);
    }
}
