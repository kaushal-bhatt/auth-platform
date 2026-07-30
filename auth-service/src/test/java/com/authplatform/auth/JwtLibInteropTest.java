package com.authplatform.auth;

import com.authplatform.auth.dto.LoginRequest;
import com.authplatform.auth.dto.RegisterRequest;
import com.authplatform.auth.dto.TokenResponse;
import com.authplatform.jwt.config.JwtLibProperties;
import com.authplatform.jwt.model.JwtClaims;
import com.authplatform.jwt.model.JwtVerificationResult;
import com.authplatform.jwt.service.JwksClient;
import com.authplatform.jwt.service.impl.JwksClientImpl;
import com.authplatform.jwt.service.impl.JwtVerificationServiceImpl;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * The capstone proof of this whole project: {@code auth-jwt-lib} (Task 4) can verify a token
 * issued by a genuinely running {@code auth-service} (Tasks 9, 10, 17) using nothing but the
 * standard RFC 7517 JWKS HTTP contract - no shared beans, no mocked verifier, no compile-time
 * reach into auth-service internals from the library side.
 * <p>
 * Every test here runs the service on a real, OS-assigned port ({@code webEnvironment =
 * RANDOM_PORT}), registers and logs in over real HTTP to obtain a genuinely issued access token,
 * and hands that token to the library's real {@link JwksClientImpl} + {@link
 * JwtVerificationServiceImpl}, pointed at the service's own live {@code GET
 * /.well-known/jwks.json}. Nothing here stubs {@code JwtVerificationService} - that is the whole
 * point.
 * <p>
 * <b>A note on the self-referential JWKS fetch and {@code RANDOM_PORT}.</b> This service's own
 * {@code JwtAuthenticationInterceptor} (wired by auth-jwt-lib's auto-configuration) also needs to
 * fetch this same JWKS endpoint whenever it verifies a bearer token for a
 * {@code @JwtTokenVerification} endpoint such as {@code GET /passkey}. That internal {@link
 * JwtLibProperties} bean binds {@code auth-platform.jwt.jwks-uri} once at context startup, from
 * {@code src/test/resources/application.yml}, which (like main's application.yml) hardcodes
 * {@code http://localhost:8080/...}. Under {@code RANDOM_PORT} the embedded server actually
 * listens on a different, OS-assigned port that is only known after startup completes, so that
 * hardcoded URI is wrong for the one test below that drives a protected endpoint end-to-end. This
 * is purely a self-reference artifact of testing a running instance's own auto-configured client
 * against its own dynamically-chosen test port - a real deployment's {@code jwks-uri} points at a
 * stable, externally-resolvable address, not "myself, on whatever port I happen to be bound to
 * right now". Because {@link JwtLibProperties} is a plain mutable
 * {@code @ConfigurationProperties} bean (not a record) and {@link JwksClientImpl} re-reads {@code
 * properties.getJwksUri()} on every refresh rather than caching it at construction, {@link
 * #protectedPasskeyEndpointAcceptsARealTokenVerifiedViaARealJwksFetchOverHttp()} repoints that
 * exact same bean instance - the one the running application already wired into its own
 * interceptor - to the correct, now-known port before making its request. No production code or
 * production configuration is touched to do this.
 */
@Testcontainers
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class JwtLibInteropTest {

    private static final String PASSWORD = "correct-horse-battery";

    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:16-alpine");

    @DynamicPropertySource
    static void configureDatasource(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
    }

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;

    /**
     * The very same {@link JwtLibProperties} bean the running application wired into its own
     * {@code JwtAuthenticationInterceptor} - see the class javadoc for why one test below needs
     * to repoint its {@code jwksUri} to the actual random port.
     */
    @Autowired
    private JwtLibProperties appJwtLibProperties;

    private String baseUrl() {
        return "http://localhost:" + port;
    }

    /**
     * Registers a fresh user and logs in over real HTTP, returning the genuinely issued token
     * pair. Every test uses its own email so the tests remain independent despite sharing one
     * Postgres container and one Spring context across the class.
     */
    private TokenResponse registerAndLogIn(String email) {
        ResponseEntity<Void> registerResponse = restTemplate.postForEntity(
            baseUrl() + "/auth/register", new RegisterRequest(email, PASSWORD), Void.class);
        assertThat(registerResponse.getStatusCode()).isEqualTo(HttpStatus.CREATED);

        TokenResponse tokens = restTemplate.postForObject(
            baseUrl() + "/auth/login", new LoginRequest(email, PASSWORD), TokenResponse.class);
        assertThat(tokens).isNotNull();
        return tokens;
    }

    /**
     * The core interop proof: a token minted by a live auth-service is verified by auth-jwt-lib's
     * real verifier, resolving the signing key purely by fetching the service's own live JWKS
     * endpoint over HTTP - zero mocks, zero shared code path beyond that HTTP call.
     */
    @Test
    void tokenIssuedByAuthServiceVerifiesAgainstItsOwnJwksViaJwtLib() {
        String email = "interop-user@example.com";
        TokenResponse tokens = registerAndLogIn(email);

        JwtLibProperties properties = new JwtLibProperties();
        properties.setJwksUri(baseUrl() + "/.well-known/jwks.json");
        properties.setExpectedIssuer("auth-service");

        JwksClientImpl jwksClient = new JwksClientImpl(properties);
        JwtVerificationServiceImpl verificationService = new JwtVerificationServiceImpl(jwksClient, properties);

        JwtVerificationResult result = verificationService.verify(tokens.accessToken());

        assertThat(result.errorMessage()).isNull();
        assertThat(result.valid()).isTrue();

        // Assert the resolved claims themselves, not just valid() - a verifier that returned
        // valid() with garbage/empty claims would still pass a valid()-only assertion.
        JwtClaims claims = result.claims();
        assertThat(claims).isNotNull();
        assertThat(claims.email()).isEqualTo(email);
        assertThat(claims.userId()).isNotNull();
    }

    /**
     * The negative control the positive test above needs to mean anything: mirrors the approach
     * in {@code JwtIssuerTest#issuedTokenIsRejectedByTheLibraryVerifierWhenThePublishedKeyIsFromAnotherKeypair}.
     * A public key from a completely unrelated keypair, published under the exact same {@code
     * kid} the real token's header names, must be rejected. If this test failed (verification
     * succeeded), the positive round-trip above would prove nothing - it would mean the verifier
     * accepts whatever key it is handed rather than actually checking the signature.
     */
    @Test
    void tokenIsRejectedWhenAnUnrelatedKeyIsPublishedUnderTheSameKid() throws Exception {
        String email = "interop-negative-control@example.com";
        TokenResponse tokens = registerAndLogIn(email);
        String keyId = SignedJWT.parse(tokens.accessToken()).getHeader().getKeyID();
        assertThat(keyId).isNotNull();

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        RSAKey unrelatedPublicJwk = new RSAKey.Builder((RSAPublicKey) generator.generateKeyPair().getPublic())
            .keyID(keyId)
            .keyUse(KeyUse.SIGNATURE)
            .build();

        // A stubbed JwksClient here (rather than the real JwksClientImpl) is deliberate: the
        // point of this control is to isolate JwtVerificationServiceImpl's signature check from
        // key resolution entirely, exactly as JwtIssuerTest's negative control does.
        JwksClient stubbedJwksClient = mock(JwksClient.class);
        when(stubbedJwksClient.getKey(keyId)).thenReturn(Optional.of(unrelatedPublicJwk));

        JwtLibProperties properties = new JwtLibProperties();
        properties.setExpectedIssuer("auth-service");

        JwtVerificationResult result =
            new JwtVerificationServiceImpl(stubbedJwksClient, properties).verify(tokens.accessToken());

        assertThat(result.valid()).isFalse();
        assertThat(result.errorMessage()).isEqualTo("invalid jwt signature");
    }

    /**
     * Until Task 17 added the JWKS endpoint, every {@code @JwtTokenVerification}-protected
     * controller test stubbed {@code JwtVerificationService} with {@code @MockBean} (see e.g.
     * {@code PasskeyControllerTest}), since there was no real JWKS endpoint to fetch from. This is
     * the first test in the project that drives a protected endpoint with a real, HTTP-issued
     * token and lets the running service's own auto-configured {@code JwtAuthenticationInterceptor}
     * verify it via a real JWKS fetch - proving the full request path (register -> login -> bearer
     * token -> interceptor -> JwksClient -> HTTP GET /.well-known/jwks.json -> signature check ->
     * controller) actually works end-to-end, not just that the two modules' classes are
     * independently unit-testable against each other.
     */
    @Test
    void protectedPasskeyEndpointAcceptsARealTokenVerifiedViaARealJwksFetchOverHttp() {
        String email = "interop-protected-endpoint@example.com";
        TokenResponse tokens = registerAndLogIn(email);

        // See the class javadoc: repoints the app's own auto-configured JwksClient at the actual
        // random port now that it is known, so its internal JWKS fetch (triggered by the request
        // below) reaches the real endpoint instead of the hardcoded test port.
        appJwtLibProperties.setJwksUri(baseUrl() + "/.well-known/jwks.json");

        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(tokens.accessToken());

        ResponseEntity<String> response = restTemplate.exchange(
            baseUrl() + "/passkey", HttpMethod.GET, new HttpEntity<>(headers), String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isEqualTo("[]");
    }

    /**
     * The other half of the proof above: the same protected endpoint must reject a request that
     * carries no bearer token at all, confirming {@code @JwtTokenVerification} enforcement is
     * actually wired up on the live HTTP path rather than only in isolated unit/MockMvc tests.
     */
    @Test
    void protectedPasskeyEndpointReturns401WithoutABearerToken() {
        ResponseEntity<String> response = restTemplate.getForEntity(baseUrl() + "/passkey", String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }
}
