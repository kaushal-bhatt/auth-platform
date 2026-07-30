package com.authplatform.auth.dto;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Mirrors {@code RegisterRequestTest}. {@link LoginRequest} already overrode {@code toString()} to
 * mask the password, but nothing asserted it — so deleting the override would have gone completely
 * unnoticed while silently turning every logged login request into a plaintext credential leak.
 */
class LoginRequestTest {

    @Test
    void toStringDoesNotContainThePasswordOrTheEmail() {
        LoginRequest request = new LoginRequest("alice@x.com", "super-secret-password");

        String result = request.toString();

        assertThat(result).doesNotContain("super-secret-password");
        // the email is masked too: this project's logging policy forbids writing email addresses
        // into logs, and toString() was the one place that contradicted it.
        assertThat(result).doesNotContain("alice@x.com");
        assertThat(result).contains("email=***");
        assertThat(result).contains("password=***");
    }

    @Test
    void accessorsStillReturnTheRealPasswordAndEmail() {
        LoginRequest request = new LoginRequest("alice@x.com", "super-secret-password");

        assertThat(request.password()).isEqualTo("super-secret-password");
        assertThat(request.email()).isEqualTo("alice@x.com");
    }
}
