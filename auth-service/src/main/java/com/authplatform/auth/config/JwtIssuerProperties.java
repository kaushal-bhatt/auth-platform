package com.authplatform.auth.config;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Positive;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * Binds the token-issuance settings.
 * <p>
 * {@code @Validated} is deliberate and load-bearing. Without it these properties bind to their
 * primitive/reference defaults when absent or misspelled, and startup stays green: a missing
 * {@code access-token-expiry-minutes} would bind to {@code 0}, so {@code /auth/login} would
 * return 200 with {@code expiresIn: 0} and an access token every consumer immediately rejects
 * as expired — a total platform outage that presents as a client bug. A missing {@code issuer}
 * would omit the {@code iss} claim, which auth-jwt-lib rejects on every request. Failing fast at
 * startup with a message naming the offending property is the only safe behaviour here.
 */
@Getter
@Setter
@Validated
@ConfigurationProperties(prefix = "auth-platform.issuer")
public class JwtIssuerProperties {

    @NotBlank
    private String issuer;

    /**
     * Value placed in the {@code aud} claim of every issued access token.
     * <p>
     * This is configuration rather than a constant because it is a cross-service contract:
     * auth-jwt-lib's {@code auth-platform.jwt.expected-audience} check is optional and is
     * currently unset, so it passes unconditionally — but the moment an operator enables it they
     * must supply this exact string. Both {@code application.yml} files set it to
     * {@code auth-platform-client} and carry a commented-out {@code expected-audience} line
     * documenting that.
     */
    @NotBlank
    private String audience;

    @Positive
    private long accessTokenExpiryMinutes;

    @Positive
    private long refreshTokenExpiryMinutes;
}
