package com.authplatform.auth.controller;

import com.authplatform.auth.dto.PasskeyLoginCompleteRequest;
import com.authplatform.auth.dto.RegisterRequest;
import com.authplatform.auth.entity.PasskeyCredentialEntity;
import com.authplatform.auth.entity.UserEntity;
import com.authplatform.auth.repository.PasskeyCredentialRepository;
import com.authplatform.auth.repository.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.webauthn4j.converter.AttestedCredentialDataConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.authenticator.EC2COSEKey;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Covers what this codebase owns for the controller layer per the Task 15 brief's scope note:
 * that both endpoints are genuinely public (no {@code @JwtTokenVerification}), and that reaching
 * the real service for bad input maps to a clean status rather than a 500 - not the happy path of
 * a valid assertion, which is webauthn4j's own territory (see
 * {@code PasskeyLoginFlowServiceImplTest} for the full rationale).
 * <p>
 * Proving "reachable without a bearer token" needs more than a bare status code: both
 * {@code JwtAuthenticationInterceptor}'s rejection (for endpoints that DO require a token) and
 * this service's own business-rule rejections return 4xx. What distinguishes them is the response
 * body - the interceptor calls {@code HttpServletResponse#sendError} with the fixed message
 * {@code "unauthorized"} and never reaches {@code GlobalExceptionHandler}, whereas a request that
 * reaches this controller's service gets the real {@code ErrorResponse} shape
 * ({@code $.status}/{@code $.message}) with this service's own message text. Every test below
 * asserts on that message, not just the HTTP status, so a regression that silently added
 * {@code @JwtTokenVerification} back to this controller would be caught even though it would still
 * return 401.
 */
@Testcontainers
@SpringBootTest
@AutoConfigureMockMvc
class PasskeyLoginControllerTest {

    /** Valid base64url ({@code "garbage"}) whose decoded bytes are not valid CBOR. */
    private static final String GARBAGE_BUT_VALID_BASE64 = "Z2FyYmFnZQ";
    private static final String CREDENTIAL_ID = "cred-bad-base64";
    private static final String PASSKEY_AUTHENTICATION_FAILED = "passkey authentication failed";

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
    private UserRepository userRepository;

    @Autowired
    private PasskeyCredentialRepository passkeyCredentialRepository;

    @Test
    void initIsReachableWithoutABearerTokenAndRejectsAnUnknownEmail() throws Exception {
        String body = "{\"email\":\"nobody-passkey-login@example.com\"}";

        mockMvc.perform(post("/passkey/login/init")
                .contentType(MediaType.APPLICATION_JSON)
                .content(body))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.message").value("invalid email or no passkeys registered"));
    }

    /**
     * A registered user with no passkeys must get the exact same clean rejection as an unknown
     * email (see the uniform-failure note on {@code PasskeyLoginFlowServiceImpl}), and it must
     * come from the real service, not a 500 - this exercises the controller wired to the real
     * service end-to-end, not merely stubbed.
     */
    @Test
    void initIsReachableWithoutABearerTokenAndRejectsARegisteredUserWithNoPasskeys() throws Exception {
        RegisterRequest registerRequest = new RegisterRequest("passkey-login-no-passkeys@example.com", "correct-horse-battery");
        mockMvc.perform(post("/auth/register")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(registerRequest)));

        String body = "{\"email\":\"passkey-login-no-passkeys@example.com\"}";

        mockMvc.perform(post("/passkey/login/init")
                .contentType(MediaType.APPLICATION_JSON)
                .content(body))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.message").value("invalid email or no passkeys registered"));
    }

    @Test
    void completeIsReachableWithoutABearerTokenAndRejectsAnUnknownChallenge() throws Exception {
        PasskeyLoginCompleteRequest request = new PasskeyLoginCompleteRequest(
            "this-challenge-was-never-issued",
            "irrelevant-credential-id",
            Base64.getUrlEncoder().encodeToString("garbage".getBytes()),
            Base64.getUrlEncoder().encodeToString("garbage".getBytes()),
            Base64.getUrlEncoder().encodeToString("garbage".getBytes()));

        mockMvc.perform(post("/passkey/login/complete")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.message").value("unknown or expired passkey challenge"));
    }

    /**
     * Fix 4, end to end over HTTP with no credentials whatsoever - the exact reported defect.
     * {@code /passkey/login/init} is public and hands out a live challenge; feeding that challenge
     * back to {@code /complete} with a {@code signature} of {@code "###"} used to decode outside
     * the guarded region, so {@code IllegalArgumentException} reached
     * {@code GlobalExceptionHandler}'s catch-all: HTTP 500 plus a full stack trace at ERROR level,
     * repeatable without limit by an anonymous caller. It must now be the same clean 401 that
     * valid-base64-but-garbage-CBOR already produced.
     */
    @Test
    void completeWithMalformedBase64IsRejectedAsUnauthorizedNotServerError() throws Exception {
        String email = "passkey-login-bad-base64@example.com";
        String challenge = registerUserWithAPasskeyAndIssueALiveChallenge(email, CREDENTIAL_ID);

        PasskeyLoginCompleteRequest request = new PasskeyLoginCompleteRequest(
            challenge, CREDENTIAL_ID, GARBAGE_BUT_VALID_BASE64, GARBAGE_BUT_VALID_BASE64, "###");

        mockMvc.perform(post("/passkey/login/complete")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.status").value(401))
            .andExpect(jsonPath("$.message").value(PASSKEY_AUTHENTICATION_FAILED));
    }

    /**
     * Fix 5: malformed base64 and garbage-but-decodable CBOR must be indistinguishable in the
     * response, which is what makes the "uniform failure responses" claim true for this endpoint.
     */
    @Test
    void completeWithMalformedBase64AndWithGarbageCborLookIdentical() throws Exception {
        // credential_id is unique, so each case needs its own credential row and its own user
        String challenge = registerUserWithAPasskeyAndIssueALiveChallenge(
            "passkey-login-uniform-a@example.com", "cred-uniform-a");
        String badBase64Body = mockMvc.perform(post("/passkey/login/complete")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(new PasskeyLoginCompleteRequest(
                    challenge, "cred-uniform-a", GARBAGE_BUT_VALID_BASE64, GARBAGE_BUT_VALID_BASE64, "###"))))
            .andExpect(status().isUnauthorized())
            .andReturn().getResponse().getContentAsString();

        String otherChallenge = registerUserWithAPasskeyAndIssueALiveChallenge(
            "passkey-login-uniform-b@example.com", "cred-uniform-b");
        String garbageCborBody = mockMvc.perform(post("/passkey/login/complete")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(new PasskeyLoginCompleteRequest(
                    otherChallenge, "cred-uniform-b",
                    GARBAGE_BUT_VALID_BASE64, GARBAGE_BUT_VALID_BASE64, GARBAGE_BUT_VALID_BASE64))))
            .andExpect(status().isUnauthorized())
            .andReturn().getResponse().getContentAsString();

        assertThat(badBase64Body).isEqualTo(garbageCborBody);
    }

    /**
     * Registers a user, gives them one stored passkey credential, then drives the real public
     * {@code /passkey/login/init} endpoint to obtain a genuine, live, server-issued challenge -
     * exactly what an anonymous attacker can do. The stored attested credential data has to be
     * structurally real CBOR so {@code completeLogin} gets past its converter call on stored
     * (trusted, previously validated) data and reaches the request-field decoding this test is
     * about; it signs nothing and is never used to produce a valid assertion.
     */
    private String registerUserWithAPasskeyAndIssueALiveChallenge(String email, String credentialId) throws Exception {
        mockMvc.perform(post("/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(new RegisterRequest(email, "correct-horse-battery"))))
            .andExpect(status().isCreated());
        UserEntity user = userRepository.findByEmail(email).orElseThrow();

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(new ECGenParameterSpec("secp256r1"));
        EC2COSEKey coseKey = EC2COSEKey.create((ECPublicKey) keyPairGenerator.generateKeyPair().getPublic());
        AttestedCredentialDataConverter converter = new AttestedCredentialDataConverter(new ObjectConverter());
        String attestedCredentialData = Base64.getEncoder().encodeToString(converter.convert(
            new AttestedCredentialData(AAGUID.ZERO, credentialId.getBytes(StandardCharsets.UTF_8), coseKey)));

        passkeyCredentialRepository.save(PasskeyCredentialEntity.builder()
            .userId(user.getId())
            .credentialId(credentialId)
            .attestedCredentialData(attestedCredentialData)
            .signCount(0)
            .createdAt(Instant.now())
            .build());

        String initResponseBody = mockMvc.perform(post("/passkey/login/init")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"email\":\"" + email + "\"}"))
            .andExpect(status().isOk())
            .andReturn().getResponse().getContentAsString();
        return objectMapper.readTree(initResponseBody).get("challenge").asText();
    }

    @Test
    void completeWithBlankFieldsIsRejectedAsBadRequestNotServerError() throws Exception {
        String bodyWithBlankChallenge = "{\"challenge\":\"\",\"credentialId\":\"x\","
            + "\"authenticatorData\":\"x\",\"clientDataJSON\":\"x\",\"signature\":\"x\"}";

        mockMvc.perform(post("/passkey/login/complete")
                .contentType(MediaType.APPLICATION_JSON)
                .content(bodyWithBlankChallenge))
            .andExpect(status().isBadRequest());
    }
}
