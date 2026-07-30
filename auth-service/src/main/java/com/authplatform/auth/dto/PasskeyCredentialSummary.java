package com.authplatform.auth.dto;

import java.time.Instant;

public record PasskeyCredentialSummary(String credentialId, Instant createdAt) {
}
