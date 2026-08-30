package com.authplatform.auth.security;

import com.authplatform.auth.config.JwtIssuerProperties;
import com.authplatform.auth.entity.CertificateEntity;
import com.authplatform.auth.service.KeysService;
import com.authplatform.jwt.config.JwtLibProperties;
import com.authplatform.jwt.model.JwtVerificationResult;
import com.authplatform.jwt.service.JwksClient;
import com.authplatform.jwt.service.impl.JwtVerificationServiceImpl;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Pins the claim/header shape that auth-jwt-lib's {@code JwtVerificationServiceImpl} and
 * {@code JwksClientImpl} depend on: the header {@code kid} must resolve to the same key id the
 * jwks endpoint publishes, and {@code iss} must match the consumer's configured expected issuer
 * (both are "auth-service" in application.yml). A mismatch on either would make every token this
 * service issues fail verification everywhere else in the platform.
 * <p>
 * It also closes the largest gap in the credential-minting path: previously this class generated
 * an RSA keypair, handed the <em>private</em> key to a mocked {@link KeysService} and then
 * discarded the public key, so nothing anywhere proved that a token this service mints is actually
 * <em>accepted</em> by the verifier every consumer runs. {@link
 * #issuedTokenIsAcceptedByTheLibraryVerifierUsingTheMatchingPublicKey()} now performs that
 * round-trip against the real {@code JwtVerificationServiceImpl}, verifying the RSA signature with
 * the public half of the same keypair.
 */
class JwtIssuerTest {

    private static final String KEY_ID = "test-key-id";
    private static final String AUDIENCE = "auth-platform-client";
    private static final long USER_ID = 42L;
    private static final String EMAIL = "user@example.com";

    private KeysService keysService;
    private JwtIssuerProperties issuerProperties;
    private JwtIssuer jwtIssuer;
    private CertificateEntity certificate;
    private RSAKey publicJwk;

    @BeforeEach
    void setUp() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();

        certificate = CertificateEntity.builder()
            .keyId(KEY_ID)
            .active(true)
            .build();

        // the public half is no longer discarded: it is what the verifier round-trip below uses,
        // exactly as KeysServiceImpl#toPublicJwk would publish it on the jwks endpoint.
        publicJwk = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
            .keyID(KEY_ID)
            .keyUse(KeyUse.SIGNATURE)
            .build();

        keysService = mock(KeysService.class);
        when(keysService.getActiveKey()).thenReturn(certificate);
        when(keysService.toPrivateKey(certificate)).thenReturn((RSAPrivateKey) keyPair.getPrivate());
        when(keysService.toPublicJwk(certificate)).thenReturn(publicJwk);

        issuerProperties = new JwtIssuerProperties();
        issuerProperties.setIssuer("auth-service");
        issuerProperties.setAudience(AUDIENCE);
        issuerProperties.setAccessTokenExpiryMinutes(15);
        issuerProperties.setRefreshTokenExpiryMinutes(43200);

        jwtIssuer = new JwtIssuer(keysService, issuerProperties);
    }

    @Test
    void issuedTokenHeaderKeyIdMatchesTheActiveCertificatesKeyId() throws Exception {
        String token = jwtIssuer.issueAccessToken(USER_ID, EMAIL, UUID.randomUUID(), Set.of());

        SignedJWT signedJWT = SignedJWT.parse(token);

        assertThat(signedJWT.getHeader().getKeyID()).isEqualTo(certificate.getKeyId());
    }

    @Test
    void issuedTokenCarriesTheGrantedRoles() throws Exception {
        String token = jwtIssuer.issueAccessToken(USER_ID, EMAIL, UUID.randomUUID(),
            Set.of("portfolio-admin"));

        SignedJWT signedJWT = SignedJWT.parse(token);

        assertThat(signedJWT.getJWTClaimsSet().getStringListClaim("roles"))
            .containsExactly("portfolio-admin");
    }

    /**
     * The claim is present-but-empty rather than absent, so a relying party reads one shape
     * instead of treating "no roles" as a separate case from "no claim". A consumer that had to
     * handle both would eventually handle only one, and the missing branch is the one that
     * defaults to letting someone in.
     */
    @Test
    void issuedTokenCarriesAnEmptyRolesClaimRatherThanOmittingIt() throws Exception {
        String token = jwtIssuer.issueAccessToken(USER_ID, EMAIL, UUID.randomUUID(), Set.of());

        SignedJWT signedJWT = SignedJWT.parse(token);

        assertThat(signedJWT.getJWTClaimsSet().getClaim("roles")).isNotNull();
        assertThat(signedJWT.getJWTClaimsSet().getStringListClaim("roles")).isEmpty();
    }

    @Test
    void issuedTokenIssuerClaimMatchesConfiguredIssuer() throws Exception {
        String token = jwtIssuer.issueAccessToken(USER_ID, EMAIL, UUID.randomUUID(), Set.of());

        SignedJWT signedJWT = SignedJWT.parse(token);

        assertThat(signedJWT.getJWTClaimsSet().getIssuer()).isEqualTo(issuerProperties.getIssuer());
    }

    @Test
    void issuedTokenExpiryMinusIssueTimeMatchesConfiguredAccessTokenLifetime() throws Exception {
        String token = jwtIssuer.issueAccessToken(USER_ID, EMAIL, UUID.randomUUID(), Set.of());

        SignedJWT signedJWT = SignedJWT.parse(token);
        Instant issuedAt = signedJWT.getJWTClaimsSet().getIssueTime().toInstant();
        Instant expiresAt = signedJWT.getJWTClaimsSet().getExpirationTime().toInstant();

        long actualLifetimeSeconds = expiresAt.getEpochSecond() - issuedAt.getEpochSecond();

        // this is the same value TokenResponse.expiresIn() reports, via
        // JwtIssuer.accessTokenExpirySeconds() - if these ever diverged, clients would refresh
        // at the wrong time relative to when the access token actually expires.
        assertThat(actualLifetimeSeconds).isEqualTo(jwtIssuer.accessTokenExpirySeconds());
    }

    /**
     * rfc 8725 section 3.1: {@code JwtVerificationServiceImpl} rejects outright any algorithm that
     * is not exactly {@code RS256}, before it even looks up the key. Nothing asserted the header
     * value this service actually emits.
     */
    @Test
    void issuedTokenHeaderAlgorithmIsExactlyRs256() throws Exception {
        String token = jwtIssuer.issueAccessToken(USER_ID, EMAIL, UUID.randomUUID(), Set.of());

        SignedJWT signedJWT = SignedJWT.parse(token);

        assertThat(signedJWT.getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
        assertThat(signedJWT.getHeader().getAlgorithm().getName()).isEqualTo("RS256");
    }

    /**
     * {@code JwtVerificationServiceImpl} fails a token with a null {@code sub}, and publishes it to
     * consumers as {@code JwtClaims.userId} — a String. Pinning the exact rendering of the numeric
     * user id keeps consumers' {@code Long.parseLong(claims.userId())} working.
     */
    @Test
    void issuedTokenSubjectIsTheUserIdRenderedAsAString() throws Exception {
        String token = jwtIssuer.issueAccessToken(USER_ID, EMAIL, UUID.randomUUID(), Set.of());

        SignedJWT signedJWT = SignedJWT.parse(token);

        assertThat(signedJWT.getJWTClaimsSet().getSubject()).isEqualTo("42");
    }

    @Test
    void issuedTokenCarriesTheEmailAndSessionClaims() throws Exception {
        UUID sessionId = UUID.randomUUID();

        String token = jwtIssuer.issueAccessToken(USER_ID, EMAIL, sessionId, Set.of());

        SignedJWT signedJWT = SignedJWT.parse(token);
        assertThat(signedJWT.getJWTClaimsSet().getClaim("email")).isEqualTo(EMAIL);
        assertThat(signedJWT.getJWTClaimsSet().getClaim("sess")).isEqualTo(sessionId.toString());
    }

    /**
     * The audience is configuration ({@code auth-platform.issuer.audience}), not a hardcoded
     * literal, precisely so that an operator who later switches on auth-jwt-lib's optional
     * {@code auth-platform.jwt.expected-audience} check has a documented value to supply.
     */
    @Test
    void issuedTokenAudienceMatchesTheConfiguredAudience() throws Exception {
        String token = jwtIssuer.issueAccessToken(USER_ID, EMAIL, UUID.randomUUID(), Set.of());

        SignedJWT signedJWT = SignedJWT.parse(token);

        assertThat(signedJWT.getJWTClaimsSet().getAudience()).containsExactly(AUDIENCE);
        assertThat(signedJWT.getJWTClaimsSet().getAudience()).containsExactly(issuerProperties.getAudience());
    }

    /**
     * The round-trip. Issues a token with the production {@link JwtIssuer}, then verifies it with
     * auth-jwt-lib's real {@code JwtVerificationServiceImpl} — the same class every consumer in the
     * platform runs — backed by a {@link JwksClient} serving {@code keysService.toPublicJwk(...)},
     * i.e. the public half of the signing keypair. Because
     * {@code JwtVerificationServiceImpl#doVerify} runs {@code signedJWT.verify(new
     * RSASSAVerifier(key))}, a {@code valid()} result is genuine cryptographic proof that the
     * signature this service produces checks out against the published public key. The expected
     * audience is switched ON here so that the optional {@code aud} check is exercised too.
     */
    @Test
    void issuedTokenIsAcceptedByTheLibraryVerifierUsingTheMatchingPublicKey() {
        UUID sessionId = UUID.randomUUID();
        String token = jwtIssuer.issueAccessToken(USER_ID, EMAIL, sessionId, Set.of());

        // exactly what KeysServiceImpl#toPublicJwk would publish on the jwks endpoint for the
        // certificate that signed this token. Resolved before the stubbing call below, because
        // Mockito forbids invoking one mock while another's stubbing is still unfinished.
        RSAKey published = keysService.toPublicJwk(certificate);
        assertThat(published).isSameAs(publicJwk);

        JwksClient jwksClient = mock(JwksClient.class);
        when(jwksClient.getKey(KEY_ID)).thenReturn(Optional.of(published));

        JwtLibProperties libProperties = new JwtLibProperties();
        libProperties.setExpectedIssuer("auth-service");
        libProperties.setExpectedAudience(AUDIENCE);

        JwtVerificationResult result = new JwtVerificationServiceImpl(jwksClient, libProperties).verify(token);

        assertThat(result.errorMessage()).isNull();
        assertThat(result.valid()).isTrue();
        assertThat(result.claims().userId()).isEqualTo("42");
        assertThat(result.claims().email()).isEqualTo(EMAIL);
        assertThat(result.claims().sessionId()).isEqualTo(sessionId.toString());
        assertThat(result.claims().issuer()).isEqualTo("auth-service");
        assertThat(result.claims().audience()).isEqualTo(AUDIENCE);
    }

    /**
     * The negative control for the round-trip above: proves the verifier is actually checking the
     * signature rather than trusting whatever it is handed. A public key from a <em>different</em>
     * keypair, published under the same {@code kid}, must be rejected — if this passed, the
     * positive round-trip would prove nothing.
     */
    @Test
    void issuedTokenIsRejectedByTheLibraryVerifierWhenThePublishedKeyIsFromAnotherKeypair() throws Exception {
        String token = jwtIssuer.issueAccessToken(USER_ID, EMAIL, UUID.randomUUID(), Set.of());

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        RSAKey unrelatedPublicJwk = new RSAKey.Builder((RSAPublicKey) generator.generateKeyPair().getPublic())
            .keyID(KEY_ID)
            .keyUse(KeyUse.SIGNATURE)
            .build();

        JwksClient jwksClient = mock(JwksClient.class);
        when(jwksClient.getKey(KEY_ID)).thenReturn(Optional.of(unrelatedPublicJwk));

        JwtLibProperties libProperties = new JwtLibProperties();
        libProperties.setExpectedIssuer("auth-service");

        JwtVerificationResult result = new JwtVerificationServiceImpl(jwksClient, libProperties).verify(token);

        assertThat(result.valid()).isFalse();
        assertThat(result.errorMessage()).isEqualTo("invalid jwt signature");
    }
}
