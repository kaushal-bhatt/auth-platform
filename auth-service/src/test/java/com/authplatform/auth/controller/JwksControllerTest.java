package com.authplatform.auth.controller;

import com.authplatform.auth.entity.CertificateEntity;
import com.authplatform.auth.repository.CertificateRepository;
import com.authplatform.auth.security.KeyProtector;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * {@code /.well-known/jwks.json} must be reachable with no bearer token (it is what every
 * verifier - including this same service's own {@code auth-jwt-lib} interceptor via its
 * {@code JwksClient} - fetches to obtain the keys used to verify bearer tokens in the first
 * place), must publish every stored key (not just the active one, see {@link JwksController}'s
 * javadoc), and must never leak private key material.
 */
@Testcontainers
@SpringBootTest
@AutoConfigureMockMvc
class JwksControllerTest {

    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:16-alpine");

    @DynamicPropertySource
    static void configureDatasource(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
    }

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private KeyProtector keyProtector;

    /** RSA parameter names that only ever appear on a private JWK per RFC 7518 sec. 6.3.2. */
    private static final Set<String> PRIVATE_RSA_PARAMETER_NAMES = Set.of("d", "p", "q", "dp", "dq", "qi");

    private CertificateEntity persistExtraCertificate(boolean active) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();

        CertificateEntity certificate = CertificateEntity.builder()
            .keyId("extra-key-" + UUID.randomUUID())
            .publicKey(Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()))
            .privateKeyEncrypted(keyProtector.encrypt(
                Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded())))
            .active(active)
            .build();
        return certificateRepository.save(certificate);
    }

    @Test
    void jwksEndpointReturnsAtLeastOnePublicKey() throws Exception {
        mockMvc.perform(get("/.well-known/jwks.json"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.keys").isArray())
            .andExpect(jsonPath("$.keys[0].kid").isNotEmpty())
            .andExpect(jsonPath("$.keys[0].kty").value("RSA"));
    }

    /**
     * The endpoint carries no {@code @JwtTokenVerification} annotation and no Authorization
     * header is sent here - proving a verifier can fetch the keys with zero prior
     * authentication, which is required since these keys are precisely what any authentication
     * would need to be verified against.
     */
    @Test
    void jwksEndpointIsPubliclyReachableWithoutABearerToken() throws Exception {
        mockMvc.perform(get("/.well-known/jwks.json"))
            .andExpect(status().isOk());
    }

    /**
     * The single most important assertion in this test class: a JWKS response is public-facing
     * by design, so if private RSA parameters ever leaked into it the entire platform's signing
     * key would be compromised. Every key built by {@code KeysServiceImpl#toPublicJwk} comes only
     * from an {@code RSAPublicKey}, so this also guards against a future regression that swaps in
     * a private-key-carrying JWK by mistake.
     */
    @Test
    void jwksResponseContainsNoPrivateKeyMaterial() throws Exception {
        persistExtraCertificate(false);

        String body = mockMvc.perform(get("/.well-known/jwks.json"))
            .andExpect(status().isOk())
            .andReturn().getResponse().getContentAsString();

        assertThat(body).doesNotContain("privateKeyEncrypted");

        JsonNode root = objectMapper.readTree(body);
        for (JsonNode key : root.get("keys")) {
            Iterator<String> fieldNames = key.fieldNames();
            while (fieldNames.hasNext()) {
                String fieldName = fieldNames.next();
                assertThat(PRIVATE_RSA_PARAMETER_NAMES)
                    .as("jwk with kid=%s must not expose private RSA parameter '%s'",
                        key.get("kid"), fieldName)
                    .doesNotContain(fieldName);
            }
        }
    }

    /**
     * A rotated-out key (active = false) must still be published: a token it signed remains
     * valid until it expires, and a verifier resolves the signing key by kid, not by "is this
     * the currently active key". Every stored key must appear with its own distinct kid.
     * <p>
     * Both extras are persisted as {@code active = false} (rather than one active, one not):
     * there is already an active key from this context's startup self-check, and the partial
     * unique index added in this task allows only one {@code active = true} row at a time - so
     * this test, like production key rotation, models "rotated out" keys rather than trying to
     * force a second concurrently-active one.
     */
    @Test
    void allStoredKeysAppearInTheKeysArrayWithDistinctKids() throws Exception {
        CertificateEntity rotatedOutExtraOne = persistExtraCertificate(false);
        CertificateEntity rotatedOutExtraTwo = persistExtraCertificate(false);

        String body = mockMvc.perform(get("/.well-known/jwks.json"))
            .andExpect(status().isOk())
            .andReturn().getResponse().getContentAsString();

        JsonNode keys = objectMapper.readTree(body).get("keys");
        List<String> kids = keys.findValuesAsText("kid");

        assertThat(kids).contains(rotatedOutExtraOne.getKeyId(), rotatedOutExtraTwo.getKeyId());
        assertThat(kids).doesNotHaveDuplicates();
    }

    /**
     * On a genuinely empty database the endpoint must still return a valid, non-empty JWKS
     * (containing the first generated key), never an empty {@code keys} array and never an
     * error - {@code KeysServiceImpl} already generates a key at startup via its
     * {@code InitializingBean} check, and {@code getAllPublicJwks()} additionally falls back to
     * {@code getActiveKey()} if the table is ever found empty at request time.
     */
    @Test
    void jwksEndpointReturnsAValidKeySetEvenOnACompletelyEmptyDatabase() throws Exception {
        certificateRepository.deleteAll();
        assertThat(certificateRepository.count()).isZero();

        mockMvc.perform(get("/.well-known/jwks.json"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.keys").isArray())
            .andExpect(jsonPath("$.keys.length()").value(1))
            .andExpect(jsonPath("$.keys[0].kid").isNotEmpty())
            .andExpect(jsonPath("$.keys[0].kty").value("RSA"));

        assertThat(certificateRepository.count()).isEqualTo(1);
    }
}
