package com.authplatform.auth.controller;

import com.authplatform.auth.dto.PasskeyRegisterCompleteRequest;
import com.authplatform.auth.dto.RegisterRequest;
import com.authplatform.auth.entity.UserEntity;
import com.authplatform.auth.repository.UserRepository;
import com.authplatform.jwt.model.JwtClaims;
import com.authplatform.jwt.model.JwtVerificationResult;
import com.authplatform.jwt.service.JwtVerificationService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Instant;
import java.util.Base64;

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Covers exactly what this codebase owns per the Task 14 brief's scope note: auth-protection of
 * both endpoints, correct rp/user info in the init response, challenge-ownership/malformed-input
 * rejection on complete - not the happy path of a genuinely valid attestation, which is
 * webauthn4j's own well-tested territory (see {@code PasskeyRegistrationServiceImplTest} and the
 * class javadoc there for the full rationale).
 * <p>
 * {@code JwtVerificationService} is stubbed with {@code @MockBean} for the "with a valid token"
 * cases rather than driven end-to-end through a real JWKS HTTP round trip: no controller in this
 * codebase yet serves {@code auth-platform.jwt.jwks-uri} (there is no
 * {@code /.well-known/jwks.json} endpoint anywhere in the source tree), so
 * {@code JwksClientImpl} would attempt a real outbound HTTP call to {@code localhost:8080} in a
 * {@code @AutoConfigureMockMvc} test (which binds no real port) and every such call would fail -
 * a pre-existing infrastructure gap orthogonal to this task, not something Task 14 introduces or
 * should paper over by building a JWKS-serving endpoint. Stubbing the verification result still
 * exercises the real thing this class needs to prove: that {@code @JwtTokenVerification} is
 * enforced on both endpoints and that the controller correctly reads the acting user's id off the
 * verified {@link JwtClaims}, not from anywhere in the request body. The "reject requests with no
 * token at all" tests do not touch the mock at all - {@code JwtAuthenticationInterceptor} rejects
 * before ever calling {@code JwtVerificationService.verify(..)} when no bearer token is present -
 * so those are exercised against the real, unmocked authentication path.
 */
@Testcontainers
@SpringBootTest
@AutoConfigureMockMvc
class PasskeyRegistrationControllerTest {

    private static final String VALID_TOKEN = "stubbed-valid-access-token";

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

    @MockBean
    private JwtVerificationService jwtVerificationService;

    private String registerUserAndStubValidToken(String email) throws Exception {
        RegisterRequest registerRequest = new RegisterRequest(email, "correct-horse-battery");
        mockMvc.perform(post("/auth/register")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(registerRequest)));

        UserEntity user = userRepository.findByEmail(email).orElseThrow();

        JwtClaims claims = new JwtClaims(
            user.getId().toString(), email, "auth-service", "auth-platform-client",
            "stub-session", Instant.now(), Instant.now().plusSeconds(900));
        when(jwtVerificationService.verify(VALID_TOKEN)).thenReturn(JwtVerificationResult.success(claims));

        return VALID_TOKEN;
    }

    @Test
    void initWithoutBearerTokenIsRejectedAsUnauthorized() throws Exception {
        mockMvc.perform(post("/passkey/register/init"))
            .andExpect(status().isUnauthorized());
    }

    @Test
    void completeWithoutBearerTokenIsRejectedAsUnauthorized() throws Exception {
        PasskeyRegisterCompleteRequest request = new PasskeyRegisterCompleteRequest(
            "any-challenge", "any-credential-id", "any-attestation", "any-client-data");

        mockMvc.perform(post("/passkey/register/complete")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
            .andExpect(status().isUnauthorized());
    }

    @Test
    void initWithAnInvalidBearerTokenIsRejectedAsUnauthorized() throws Exception {
        when(jwtVerificationService.verify("garbage-token"))
            .thenReturn(JwtVerificationResult.failure("bad signature"));

        mockMvc.perform(post("/passkey/register/init")
                .header("Authorization", "Bearer garbage-token"))
            .andExpect(status().isUnauthorized());
    }

    @Test
    void initWithValidTokenReturnsChallengeAndConfiguredRpInfo() throws Exception {
        String accessToken = registerUserAndStubValidToken("passkey-init-user@example.com");

        mockMvc.perform(post("/passkey/register/init")
                .header("Authorization", "Bearer " + accessToken))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.challenge").isNotEmpty())
            .andExpect(jsonPath("$.userName").value("passkey-init-user@example.com"))
            .andExpect(jsonPath("$.rpId").value("localhost"))
            .andExpect(jsonPath("$.rpName").value("Auth Platform"))
            .andExpect(jsonPath("$.pubKeyCredParams[0].type").value("public-key"))
            .andExpect(jsonPath("$.pubKeyCredParams[0].alg").value(-7));
    }

    @Test
    void completeWithBlankFieldsIsRejectedAsBadRequest() throws Exception {
        String accessToken = registerUserAndStubValidToken("passkey-blank-user@example.com");
        String bodyWithBlankChallenge = "{\"challenge\":\"\",\"credentialId\":\"x\","
            + "\"attestationObject\":\"x\",\"clientDataJSON\":\"x\"}";

        mockMvc.perform(post("/passkey/register/complete")
                .header("Authorization", "Bearer " + accessToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content(bodyWithBlankChallenge))
            .andExpect(status().isBadRequest());
    }

    /**
     * Exercises the endpoint end-to-end with a valid token but an unknown challenge: proves the
     * controller is wired to the real service (not protected-but-dead), and that the
     * "unknown/expired challenge" business rule surfaces as 400, not 401/500.
     */
    @Test
    void completeWithUnknownChallengeIsRejectedAsBadRequest() throws Exception {
        String accessToken = registerUserAndStubValidToken("passkey-unknown-challenge-user@example.com");
        PasskeyRegisterCompleteRequest request = new PasskeyRegisterCompleteRequest(
            "this-challenge-was-never-issued",
            "irrelevant-credential-id",
            Base64.getUrlEncoder().encodeToString("garbage".getBytes()),
            Base64.getUrlEncoder().encodeToString("garbage".getBytes()));

        mockMvc.perform(post("/passkey/register/complete")
                .header("Authorization", "Bearer " + accessToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.message").value("unknown or expired passkey challenge"));
    }

    /**
     * Fix 4, end to end over HTTP: an {@code attestationObject} that is not valid base64url used to
     * decode outside the {@code ValidationException | DataConversionException} guard, so
     * {@code IllegalArgumentException} reached {@code GlobalExceptionHandler}'s catch-all as HTTP
     * 500 with a full stack trace at ERROR level. It must be the same clean 400 that
     * valid-base64-but-garbage-CBOR already produced.
     */
    @Test
    void completeWithMalformedBase64IsRejectedAsBadRequestNotServerError() throws Exception {
        String accessToken = registerUserAndStubValidToken("passkey-register-bad-base64@example.com");
        String initResponseBody = mockMvc.perform(post("/passkey/register/init")
                .header("Authorization", "Bearer " + accessToken))
            .andExpect(status().isOk())
            .andReturn().getResponse().getContentAsString();
        String liveChallenge = objectMapper.readTree(initResponseBody).get("challenge").asText();

        PasskeyRegisterCompleteRequest request = new PasskeyRegisterCompleteRequest(
            liveChallenge, "irrelevant-credential-id", "###", "Z2FyYmFnZQ");

        mockMvc.perform(post("/passkey/register/complete")
                .header("Authorization", "Bearer " + accessToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.status").value(400))
            .andExpect(jsonPath("$.message").value("passkey registration failed validation"));
    }

    /**
     * Fix 4: {@code sub} is a free-form string in a JWT (RFC 7519 4.1.2), so a signature-valid token
     * from the configured issuer can carry a non-numeric subject. The controller's bare
     * {@code Long.valueOf(claims.userId())} threw {@link NumberFormatException} past the handler
     * into {@code GlobalExceptionHandler}'s catch-all as HTTP 500 with a full stack trace; such a
     * token identifies no user of this service, so it must be a 401.
     */
    @Test
    void aVerifiedTokenWithANonNumericSubjectIsRejectedAsUnauthorizedNotServerError() throws Exception {
        String token = "stubbed-token-with-non-numeric-sub";
        JwtClaims claims = new JwtClaims(
            "not-a-number", "someone@example.com", "auth-service", "auth-platform-client",
            "stub-session", Instant.now(), Instant.now().plusSeconds(900));
        when(jwtVerificationService.verify(token)).thenReturn(JwtVerificationResult.success(claims));

        mockMvc.perform(post("/passkey/register/init")
                .header("Authorization", "Bearer " + token))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.message").value("unauthorized"));
    }

    /**
     * Pins security point 1 (challenge ownership): a valid, verified token for user A must not be
     * able to complete a registration bound to a challenge issued to user B.
     */
    @Test
    void completeRejectsAChallengeIssuedToADifferentAuthenticatedUser() throws Exception {
        String userAToken = registerUserAndStubValidToken("passkey-user-a@example.com");
        String userBEmail = "passkey-user-b@example.com";
        mockMvc.perform(post("/auth/register")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(new RegisterRequest(userBEmail, "correct-horse-battery"))));
        UserEntity userB = userRepository.findByEmail(userBEmail).orElseThrow();

        // issue a real challenge for user B via user B's own /init call
        JwtClaims userBClaims = new JwtClaims(
            userB.getId().toString(), userBEmail, "auth-service", "auth-platform-client",
            "stub-session-b", Instant.now(), Instant.now().plusSeconds(900));
        String userBToken = "stubbed-valid-access-token-user-b";
        when(jwtVerificationService.verify(userBToken)).thenReturn(JwtVerificationResult.success(userBClaims));

        String initResponseBody = mockMvc.perform(post("/passkey/register/init")
                .header("Authorization", "Bearer " + userBToken))
            .andExpect(status().isOk())
            .andReturn().getResponse().getContentAsString();
        String userBChallenge = objectMapper.readTree(initResponseBody).get("challenge").asText();

        // user A now tries to complete registration using user B's challenge
        PasskeyRegisterCompleteRequest request = new PasskeyRegisterCompleteRequest(
            userBChallenge,
            "irrelevant-credential-id",
            Base64.getUrlEncoder().encodeToString("garbage".getBytes()),
            Base64.getUrlEncoder().encodeToString("garbage".getBytes()));

        mockMvc.perform(post("/passkey/register/complete")
                .header("Authorization", "Bearer " + userAToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.message").value("passkey challenge does not belong to this user"));
    }
}
