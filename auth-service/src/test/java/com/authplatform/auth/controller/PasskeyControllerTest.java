package com.authplatform.auth.controller;

import com.authplatform.auth.dto.RegisterRequest;
import com.authplatform.auth.entity.PasskeyCredentialEntity;
import com.authplatform.auth.entity.UserEntity;
import com.authplatform.auth.repository.PasskeyCredentialRepository;
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

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Follows the same {@code @MockBean JwtVerificationService} pattern established by
 * {@code PasskeyRegistrationControllerTest} rather than driving a real login round trip: no
 * {@code /.well-known/jwks.json} endpoint existed yet at the time that pattern was set (Task
 * 17 adds it), and stubbing verification still exercises the real thing this class needs to
 * prove - that {@code @JwtTokenVerification} is enforced and the controller reads the acting
 * user id only from the verified {@link JwtClaims}, never from the path or request body.
 */
@Testcontainers
@SpringBootTest
@AutoConfigureMockMvc
class PasskeyControllerTest {

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

    @MockBean
    private JwtVerificationService jwtVerificationService;

    private String registerUserAndStubValidToken(String email, String token) throws Exception {
        RegisterRequest registerRequest = new RegisterRequest(email, "correct-horse-battery");
        mockMvc.perform(post("/auth/register")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(registerRequest)));

        UserEntity user = userRepository.findByEmail(email).orElseThrow();

        JwtClaims claims = new JwtClaims(
            user.getId().toString(), email, "auth-service", "auth-platform-client",
            "stub-session", Instant.now(), Instant.now().plusSeconds(900));
        when(jwtVerificationService.verify(token)).thenReturn(JwtVerificationResult.success(claims));

        return user.getId().toString();
    }

    private PasskeyCredentialEntity savePasskey(Long userId, String credentialId) {
        return passkeyCredentialRepository.save(PasskeyCredentialEntity.builder()
            .userId(userId)
            .credentialId(credentialId)
            .attestedCredentialData("irrelevant-attested-data")
            .signCount(0)
            .build());
    }

    @Test
    void listReturnsEmptyArrayForUserWithNoPasskeys() throws Exception {
        registerUserAndStubValidToken("no-passkeys-list@example.com", "token-no-passkeys");

        mockMvc.perform(get("/passkey").header("Authorization", "Bearer token-no-passkeys"))
            .andExpect(status().isOk())
            .andExpect(content().json("[]"));
    }

    @Test
    void listRejectsRequestWithoutToken() throws Exception {
        mockMvc.perform(get("/passkey"))
            .andExpect(status().isUnauthorized());
    }

    /**
     * Fix 4: {@code sub} is a free-form string in a JWT (RFC 7519 4.1.2), so a signature-valid token
     * from the configured issuer can carry a non-numeric subject. The controller's bare
     * {@code Long.valueOf(claims.userId())} threw {@link NumberFormatException} past the handler
     * into {@code GlobalExceptionHandler}'s catch-all as HTTP 500 with a full stack trace; such a
     * token identifies no user of this service, so it must be a 401. Pinned on both handler methods,
     * since each resolves the caller independently.
     */
    @Test
    void aVerifiedTokenWithANonNumericSubjectIsRejectedAsUnauthorizedNotServerError() throws Exception {
        String token = "token-non-numeric-sub";
        JwtClaims claims = new JwtClaims(
            "not-a-number", "someone@example.com", "auth-service", "auth-platform-client",
            "stub-session", Instant.now(), Instant.now().plusSeconds(900));
        when(jwtVerificationService.verify(token)).thenReturn(JwtVerificationResult.success(claims));

        mockMvc.perform(get("/passkey").header("Authorization", "Bearer " + token))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.message").value("unauthorized"));

        mockMvc.perform(delete("/passkey/anything").header("Authorization", "Bearer " + token))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.message").value("unauthorized"));
    }

    @Test
    void deleteReturns404ForUnknownCredential() throws Exception {
        registerUserAndStubValidToken("delete-unknown@example.com", "token-delete-unknown");

        mockMvc.perform(delete("/passkey/does-not-exist").header("Authorization", "Bearer token-delete-unknown"))
            .andExpect(status().isNotFound());
    }

    /**
     * Pins the cross-user isolation guarantee: user B's credential must 404 for user A, not
     * 403 (which would confirm the credential exists) and not 200 (which would delete someone
     * else's passkey). The controller must be filtering the lookup on the caller's own userId.
     */
    @Test
    void deleteReturns404WhenCredentialBelongsToADifferentUser() throws Exception {
        String userAId = registerUserAndStubValidToken("passkey-delete-user-a@example.com", "token-delete-user-a");
        String userBId = registerUserAndStubValidToken("passkey-delete-user-b@example.com", "token-delete-user-b");
        PasskeyCredentialEntity userBCredential = savePasskey(Long.valueOf(userBId), "user-b-credential-id");

        mockMvc.perform(delete("/passkey/" + userBCredential.getCredentialId())
                .header("Authorization", "Bearer token-delete-user-a"))
            .andExpect(status().isNotFound());

        // and it must still exist afterwards - user A's rejected request must not have deleted it
        org.assertj.core.api.Assertions.assertThat(
                passkeyCredentialRepository.findByCredentialId(userBCredential.getCredentialId()))
            .isPresent();

        // sanity: user A id was registered distinctly from user B, ruling out an accidental
        // same-user false pass
        org.assertj.core.api.Assertions.assertThat(userAId).isNotEqualTo(userBId);
    }

    /**
     * Pins that listing is scoped to the caller: two users each with one passkey must each see
     * only their own credential id, never the other user's.
     */
    @Test
    void listReturnsOnlyTheCallersOwnCredentials() throws Exception {
        String userAId = registerUserAndStubValidToken("passkey-list-user-a@example.com", "token-list-user-a");
        String userBId = registerUserAndStubValidToken("passkey-list-user-b@example.com", "token-list-user-b");
        savePasskey(Long.valueOf(userAId), "user-a-only-credential");
        savePasskey(Long.valueOf(userBId), "user-b-only-credential");

        mockMvc.perform(get("/passkey").header("Authorization", "Bearer token-list-user-a"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.length()").value(1))
            .andExpect(jsonPath("$[0].credentialId").value("user-a-only-credential"));

        mockMvc.perform(get("/passkey").header("Authorization", "Bearer token-list-user-b"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.length()").value(1))
            .andExpect(jsonPath("$[0].credentialId").value("user-b-only-credential"));
    }

    /**
     * A credential id is base64url text (RFC 4648 sec. 5: alphabet includes '-' and '_', never
     * '+' or '/'), and the column is VARCHAR(1400) to accommodate long ids. Neither legal
     * base64url character requires percent-encoding, and this project's default Spring Boot
     * path-matching (PathPatternParser, suffix pattern matching off) does not truncate at '.'
     * the way legacy AntPathMatcher configurations could - so a long id containing both '-' and
     * '_' must round-trip through the path variable intact and reach the repository lookup
     * unmodified, surfacing as an ordinary 404 (unknown credential), not a 400/500 from routing
     * or decoding.
     */
    @Test
    void deleteHandlesALongBase64UrlCredentialIdWithoutRoutingOrDecodingErrors() throws Exception {
        registerUserAndStubValidToken("delete-base64url@example.com", "token-delete-base64url");
        String longBase64UrlId = "A-b_C-d_" + "E".repeat(200) + "-f_1234567890";

        mockMvc.perform(delete("/passkey/" + longBase64UrlId)
                .header("Authorization", "Bearer token-delete-base64url"))
            .andExpect(status().isNotFound());
    }
}
