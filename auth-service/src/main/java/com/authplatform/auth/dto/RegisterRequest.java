package com.authplatform.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record RegisterRequest(
    @Email @NotBlank String email,
    // 72 is BCrypt's real limit. @Size still counts UTF-16 chars, not UTF-8 bytes, so
    // RegistrationServiceImpl additionally enforces the true byte-length limit.
    @NotBlank @Size(min = 8, max = 72) String password
) {

    /**
     * Trims surrounding whitespace off the email before {@code @Email} bean validation runs
     * (Hibernate Validator's {@code @Email} rejects a padded value outright, so trimming must
     * happen here rather than only later in RegistrationServiceImpl). The password is left
     * untouched - it is never appropriate to silently alter credential input.
     */
    public RegisterRequest {
        if (email != null) {
            email = email.trim();
        }
    }

    /**
     * Masks the password so that any future request-logging filter, debug statement, or
     * error message that interpolates this DTO cannot leak the plaintext credential.
     * <p>
     * The email is masked for the same reason: this project has a stated policy against writing
     * email addresses into logs (see {@code GlobalExceptionHandler}, which refuses to log the
     * postgres detail message for exactly that reason), and printing it here was the one place
     * that policy was contradicted. The {@link #email()} accessor still returns it in full - only
     * {@code toString()} changes.
     */
    @Override
    public String toString() {
        return "RegisterRequest[email=***, password=***]";
    }
}
