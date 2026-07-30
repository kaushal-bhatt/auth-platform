package com.authplatform.auth.config;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * Binds the WebAuthn relying-party settings that anchor the whole registration/authentication
 * ceremony's security model.
 * <p>
 * {@code @Validated} is deliberate, mirroring {@link JwtIssuerProperties}: without it, a missing
 * or blank {@code relying-party-id}/{@code origin} would bind to {@code null} and startup would
 * stay green, only for every WebAuthn ceremony to fail deep inside webauthn4j's validator with a
 * {@code NullPointerException} or a confusing {@code ValidationException} instead of a clear
 * startup error naming the offending property.
 */
@Getter
@Setter
@Validated
@ConfigurationProperties(prefix = "auth-platform.webauthn")
public class WebAuthnProperties {

    @NotBlank
    private String relyingPartyId;

    @NotBlank
    private String relyingPartyName;

    @NotBlank
    private String origin;
}
