package com.authplatform.auth.dto;

import jakarta.validation.constraints.NotBlank;

public record LoginRequest(@NotBlank String email, @NotBlank String password) {

    /**
     * Masks the password so that any future request-logging filter, debug statement, or
     * error message that interpolates this DTO cannot leak the plaintext credential. Mirrors
     * RegisterRequest's toString override.
     * <p>
     * The email is masked for the same reason: this project has a stated policy against writing
     * email addresses into logs (see {@code GlobalExceptionHandler}, which refuses to log the
     * postgres detail message for exactly that reason), and printing it here was the one place
     * that policy was contradicted. The {@link #email()} accessor still returns it in full - only
     * {@code toString()} changes.
     */
    @Override
    public String toString() {
        return "LoginRequest[email=***, password=***]";
    }
}
