package com.authplatform.auth.dto;

import jakarta.validation.constraints.NotBlank;

public record PasskeyRegisterCompleteRequest(
    @NotBlank String challenge,
    @NotBlank String credentialId,
    @NotBlank String attestationObject,
    @NotBlank String clientDataJSON
) {
}
