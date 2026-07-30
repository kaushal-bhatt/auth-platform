package com.authplatform.jwt.model;

import java.time.Instant;

public record JwtClaims(
    String userId,
    String email,
    String issuer,
    String audience,
    String sessionId,
    Instant issuedAt,
    Instant expiresAt
) {
}
