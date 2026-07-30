package com.authplatform.auth.dto;

import jakarta.validation.constraints.NotBlank;

public record PasskeyLoginCompleteRequest(
    @NotBlank String challenge,
    @NotBlank String credentialId,
    @NotBlank String authenticatorData,
    @NotBlank String clientDataJSON,
    @NotBlank String signature
) {
}
