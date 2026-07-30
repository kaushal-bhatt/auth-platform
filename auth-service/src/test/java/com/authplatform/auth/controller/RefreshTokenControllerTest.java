package com.authplatform.auth.controller;

import com.authplatform.auth.dto.LoginRequest;
import com.authplatform.auth.dto.RefreshRequest;
import com.authplatform.auth.dto.RegisterRequest;
import com.authplatform.auth.dto.TokenResponse;
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
class RefreshTokenControllerTest {

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

    private TokenResponse registerAndLogin(String email) throws Exception {
        RegisterRequest registerRequest = new RegisterRequest(email, "correct-horse-battery");
        mockMvc.perform(post("/auth/register")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(registerRequest)));

        LoginRequest loginRequest = new LoginRequest(email, "correct-horse-battery");
        String loginBody = mockMvc.perform(post("/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginRequest)))
            .andReturn().getResponse().getContentAsString();
        return objectMapper.readValue(loginBody, TokenResponse.class);
    }

    @Test
    void refreshRotatesTokens() throws Exception {
        TokenResponse tokens = registerAndLogin("refresh-user@example.com");

        mockMvc.perform(post("/auth/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(new RefreshRequest(tokens.refreshToken()))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.accessToken").isNotEmpty())
            .andExpect(jsonPath("$.refreshToken").value(org.hamcrest.Matchers.not(tokens.refreshToken())));
    }

    @Test
    void refreshRejectsGarbageToken() throws Exception {
        mockMvc.perform(post("/auth/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(new RefreshRequest("not-a-real-token"))))
            .andExpect(status().isUnauthorized());
    }

    /**
     * Pins the security-relevant behaviour of rotation end-to-end over HTTP: once a refresh
     * token has been redeemed, TokenServiceImpl.refresh marks it revoked, so presenting the
     * SAME (now-old) token a second time must be rejected exactly like any other invalid token
     * - not accepted, and not given any distinguishing error detail.
     */
    @Test
    void oldRefreshTokenStopsWorkingAfterRotation() throws Exception {
        TokenResponse tokens = registerAndLogin("reuse-user@example.com");

        mockMvc.perform(post("/auth/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(new RefreshRequest(tokens.refreshToken()))))
            .andExpect(status().isOk());

        mockMvc.perform(post("/auth/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(new RefreshRequest(tokens.refreshToken()))))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.message").value("refresh token is invalid"));
    }

    /**
     * A blank refreshToken in the body must fail bean validation (@NotBlank on RefreshRequest)
     * and return 400, distinct from the 401 that TokenServiceImpl.refresh itself returns for a
     * blank token that somehow reaches the service layer directly.
     */
    @Test
    void blankRefreshTokenReturnsBadRequest() throws Exception {
        String bodyWithBlankToken = "{\"refreshToken\": \"\"}";

        mockMvc.perform(post("/auth/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .content(bodyWithBlankToken))
            .andExpect(status().isBadRequest());
    }

    /**
     * A missing refreshToken field entirely (null) must also fail bean validation with 400,
     * not reach the service and come back as 401.
     */
    @Test
    void missingRefreshTokenReturnsBadRequest() throws Exception {
        String bodyWithMissingField = "{}";

        mockMvc.perform(post("/auth/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .content(bodyWithMissingField))
            .andExpect(status().isBadRequest());
    }
}
