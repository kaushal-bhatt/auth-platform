package com.authplatform.auth.config;

import java.util.List;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration-driven allow-list of origins permitted to make cross-origin requests to
 * this service. Never defaults to a wildcard: browser-based WebAuthn clients (Tasks 14/15)
 * run cross-origin to this service and must be named explicitly.
 */
@Getter
@Setter
@ConfigurationProperties(prefix = "auth-platform.cors")
public class CorsProperties {

    private List<String> allowedOrigins;
}
