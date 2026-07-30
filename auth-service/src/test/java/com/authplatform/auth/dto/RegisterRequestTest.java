package com.authplatform.auth.dto;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class RegisterRequestTest {

    @Test
    void toStringDoesNotContainThePasswordOrTheEmail() {
        RegisterRequest request = new RegisterRequest("alice@x.com", "super-secret-password");

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
        RegisterRequest request = new RegisterRequest("alice@x.com", "super-secret-password");

        assertThat(request.password()).isEqualTo("super-secret-password");
        assertThat(request.email()).isEqualTo("alice@x.com");
    }
}
