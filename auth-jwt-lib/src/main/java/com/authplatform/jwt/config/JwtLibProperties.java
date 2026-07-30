package com.authplatform.jwt.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Getter
@Setter
@ConfigurationProperties(prefix = "auth-platform.jwt")
public class JwtLibProperties {
    private String jwksUri;
    private String expectedIssuer;
    /**
     * expected {@code aud} claim value. when null or blank the audience is not enforced,
     * which preserves the historical behaviour for callers that have not configured it.
     */
    private String expectedAudience;
    private long minRefreshIntervalSeconds = 60;
    private int connectTimeoutMillis = 5000;
    private int readTimeoutMillis = 5000;
}
