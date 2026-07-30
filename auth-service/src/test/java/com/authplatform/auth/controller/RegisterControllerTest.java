package com.authplatform.auth.controller;

import com.authplatform.auth.dto.RegisterRequest;
import com.authplatform.auth.repository.UserRepository;
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

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@Testcontainers
@SpringBootTest
@AutoConfigureMockMvc
class RegisterControllerTest {

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

    @Test
    void registerCreatesUserAndReturns201() throws Exception {
        RegisterRequest request = new RegisterRequest("new-user@example.com", "correct-horse-battery");

        mockMvc.perform(post("/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
            .andExpect(status().isCreated());
    }

    @Test
    void registerRejectsDuplicateEmail() throws Exception {
        RegisterRequest request = new RegisterRequest("dup-user@example.com", "correct-horse-battery");
        String json = objectMapper.writeValueAsString(request);

        mockMvc.perform(post("/auth/register").contentType(MediaType.APPLICATION_JSON).content(json))
            .andExpect(status().isCreated());

        mockMvc.perform(post("/auth/register").contentType(MediaType.APPLICATION_JSON).content(json))
            .andExpect(status().isConflict());
    }

    @Test
    void registerRejectsShortPassword() throws Exception {
        RegisterRequest request = new RegisterRequest("short-pw@example.com", "abc");

        mockMvc.perform(post("/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
            .andExpect(status().isBadRequest());
    }

    /**
     * Pins Fix 1: registering the same email with different casing must be rejected as a
     * duplicate, and the stored value must be the lower-cased form - both sides of the
     * uniqueness check must normalise identically.
     */
    @Test
    void registerRejectsCaseVariantDuplicateEmailAndStoresLowercasedForm() throws Exception {
        RegisterRequest first = new RegisterRequest("Alice@X.com", "correct-horse-battery");
        RegisterRequest duplicate = new RegisterRequest("alice@x.com", "another-horse-battery");

        mockMvc.perform(post("/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(first)))
            .andExpect(status().isCreated());

        mockMvc.perform(post("/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(duplicate)))
            .andExpect(status().isConflict());

        Optional<com.authplatform.auth.entity.UserEntity> stored = userRepository.findByEmail("alice@x.com");
        assertThat(stored).isPresent();
        assertThat(stored.get().getEmail()).isEqualTo("alice@x.com");
    }

    /**
     * Pins Fix 1: surrounding whitespace must not be persisted, so that a later lookup by
     * the trimmed email (e.g. login in Task 10) succeeds.
     */
    @Test
    void registerTrimsWhitespaceAroundEmailBeforeStoring() throws Exception {
        RegisterRequest request = new RegisterRequest("  trimmed@x.com  ", "correct-horse-battery");

        mockMvc.perform(post("/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
            .andExpect(status().isCreated());

        Optional<com.authplatform.auth.entity.UserEntity> stored = userRepository.findByEmail("trimmed@x.com");
        assertThat(stored).isPresent();
        assertThat(stored.get().getEmail()).isEqualTo("trimmed@x.com");
    }

    /**
     * Pins Fix 2: a password whose character count is within the (now 72-char) {@code @Size}
     * limit but whose UTF-8 byte length exceeds BCrypt's real 72-byte limit must still be
     * rejected. Using "€" (3 UTF-8 bytes each) keeps the char count well under 72 while
     * pushing the byte count over it, so this would pass vacuously if only {@code @Size} were
     * relied on.
     */
    @Test
    void registerRejectsPasswordExceedingBcryptByteLimit() throws Exception {
        String multiByteOverLimitPassword = "€".repeat(25); // 25 chars, 75 UTF-8 bytes
        RegisterRequest request = new RegisterRequest("byte-limit@example.com", multiByteOverLimitPassword);

        mockMvc.perform(post("/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsBytes(request)))
            .andExpect(status().isBadRequest());
    }
}
