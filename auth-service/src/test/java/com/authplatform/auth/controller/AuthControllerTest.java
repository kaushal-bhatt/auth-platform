package com.authplatform.auth.controller;

import com.authplatform.auth.dto.LoginRequest;
import com.authplatform.auth.dto.RegisterRequest;
import com.fasterxml.jackson.databind.ObjectMapper;
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

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@Testcontainers
@SpringBootTest
@AutoConfigureMockMvc
class AuthControllerTest {

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

    @Test
    void loginReturnsTokensForValidCredentials() throws Exception {
        RegisterRequest registerRequest = new RegisterRequest("login-user@example.com", "correct-horse-battery");
        mockMvc.perform(post("/auth/register")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(registerRequest)));

        LoginRequest loginRequest = new LoginRequest("login-user@example.com", "correct-horse-battery");

        mockMvc.perform(post("/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginRequest)))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.accessToken").isNotEmpty())
            .andExpect(jsonPath("$.refreshToken").isNotEmpty());
    }

    @Test
    void loginRejectsWrongPassword() throws Exception {
        RegisterRequest registerRequest = new RegisterRequest("wrong-pw-user@example.com", "correct-horse-battery");
        mockMvc.perform(post("/auth/register")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(registerRequest)));

        LoginRequest loginRequest = new LoginRequest("wrong-pw-user@example.com", "wrong-password");

        mockMvc.perform(post("/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginRequest)))
            .andExpect(status().isUnauthorized());
    }

    /**
     * Pins the email-normalisation fix: Task 7 stores emails normalised (trimmed +
     * lower-cased), so a user registering with a lower-case email must still be able to
     * log in typing a mixed-case variant of the same address. Without normalising the
     * lookup side, this fails because "Mixed-Case-User@Example.com" != the stored
     * "mixed-case-user@example.com".
     */
    @Test
    void loginSucceedsWithMixedCaseVariantOfRegisteredEmail() throws Exception {
        RegisterRequest registerRequest = new RegisterRequest("mixed-case-user@example.com", "correct-horse-battery");
        mockMvc.perform(post("/auth/register")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(registerRequest)));

        LoginRequest loginRequest = new LoginRequest("Mixed-Case-User@Example.com", "correct-horse-battery");

        mockMvc.perform(post("/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginRequest)))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.accessToken").isNotEmpty())
            .andExpect(jsonPath("$.refreshToken").isNotEmpty());
    }

    /**
     * Pins the uniform-failure requirement: an email that was never registered must
     * produce the exact same status and message as a wrong-password attempt against a
     * real account, so a caller cannot use the response to enumerate which accounts
     * exist.
     */
    @Test
    void loginWithNonExistentEmailReturnsSameResponseAsWrongPassword() throws Exception {
        RegisterRequest registerRequest = new RegisterRequest("real-user@example.com", "correct-horse-battery");
        mockMvc.perform(post("/auth/register")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(registerRequest)));

        LoginRequest wrongPasswordRequest = new LoginRequest("real-user@example.com", "wrong-password");
        String wrongPasswordBody = mockMvc.perform(post("/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(wrongPasswordRequest)))
            .andExpect(status().isUnauthorized())
            .andReturn().getResponse().getContentAsString();

        LoginRequest noSuchUserRequest = new LoginRequest("no-such-user@example.com", "whatever-password");
        String noSuchUserBody = mockMvc.perform(post("/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(noSuchUserRequest)))
            .andExpect(status().isUnauthorized())
            .andReturn().getResponse().getContentAsString();

        org.assertj.core.api.Assertions.assertThat(noSuchUserBody).isEqualTo(wrongPasswordBody);
    }

    /**
     * Pins that the token response reports the configured access-token lifetime (15
     * minutes = 900 seconds per application.yml) rather than some other value.
     */
    @Test
    void loginReturnsConfiguredAccessTokenExpiryInSeconds() throws Exception {
        RegisterRequest registerRequest = new RegisterRequest("expiry-user@example.com", "correct-horse-battery");
        mockMvc.perform(post("/auth/register")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(registerRequest)));

        LoginRequest loginRequest = new LoginRequest("expiry-user@example.com", "correct-horse-battery");

        mockMvc.perform(post("/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginRequest)))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.expiresIn").value(900));
    }

    /**
     * Pins Fix 7d end-to-end: a truncated/malformed JSON body raises
     * {@code HttpMessageNotReadableException}, which without a dedicated handler fell through to
     * the catch-all and returned 500 (plus a full stack trace in the logs) for what is plainly a
     * client error. The response must also not echo Jackson's parse message, which quotes the
     * offending region of the body — here, the caller's password.
     */
    @Test
    void malformedJsonBodyIsRejectedAsBadRequestRatherThanServerError() throws Exception {
        String truncatedBody = "{\"email\": \"broken@example.com\", \"password\": \"super-secret-password\"";

        mockMvc.perform(post("/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(truncatedBody))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.status").value(400))
            .andExpect(jsonPath("$.message").value("malformed request body"));
    }

    @Test
    void malformedJsonBodyResponseDoesNotEchoTheRequestContent() throws Exception {
        String truncatedBody = "{\"email\": \"broken@example.com\", \"password\": \"super-secret-password\"";

        String body = mockMvc.perform(post("/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(truncatedBody))
            .andExpect(status().isBadRequest())
            .andReturn().getResponse().getContentAsString();

        org.assertj.core.api.Assertions.assertThat(body).doesNotContain("super-secret-password");
        org.assertj.core.api.Assertions.assertThat(body).doesNotContain("broken@example.com");
    }
}
