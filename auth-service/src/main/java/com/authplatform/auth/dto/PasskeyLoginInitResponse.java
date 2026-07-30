package com.authplatform.auth.dto;

import java.util.List;

public record PasskeyLoginInitResponse(
    String challenge,
    String rpId,
    List<String> allowCredentialIds,
    long timeoutMillis
) {
}
