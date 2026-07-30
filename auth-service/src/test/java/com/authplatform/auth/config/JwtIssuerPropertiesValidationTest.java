package com.authplatform.auth.config;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Proves {@link JwtIssuerProperties} genuinely fails startup — with a message that names the
 * offending property — when any of its four settings is missing, blank, or non-positive.
 * <p>
 * This is not defensive theatre. Before validation was added these bound to primitive/reference
 * defaults and startup stayed green: a typo'd {@code access-token-expiry-minutes} bound to
 * {@code 0}, so {@code /auth/login} answered 200 with {@code expiresIn: 0} and an access token
 * every consumer rejected as already expired — a platform-wide outage presenting as a client bug.
 * A missing {@code issuer} omitted the {@code iss} claim, which auth-jwt-lib rejects on every
 * request. Each test below breaks exactly one property and leaves the other three valid, so a
 * failure identifies which constraint regressed.
 * <p>
 * Modelled on {@code KeyProtectionSecretOverrideTest}: an {@link ApplicationContextRunner} rather
 * than a full {@code @SpringBootTest}, because the thing under test is the binding itself.
 */
class JwtIssuerPropertiesValidationTest {

    private static final String ISSUER = "auth-platform.issuer.issuer=auth-service";
    private static final String AUDIENCE = "auth-platform.issuer.audience=auth-platform-client";
    private static final String ACCESS_EXPIRY = "auth-platform.issuer.access-token-expiry-minutes=15";
    private static final String REFRESH_EXPIRY = "auth-platform.issuer.refresh-token-expiry-minutes=43200";

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
        .withUserConfiguration(JwtIssuerPropertiesTestConfig.class);

    @Test
    void bindsSuccessfullyWhenEveryPropertyIsPresentAndValid() {
        contextRunner
            .withPropertyValues(ISSUER, AUDIENCE, ACCESS_EXPIRY, REFRESH_EXPIRY)
            .run(context -> {
                assertThat(context).hasSingleBean(JwtIssuerProperties.class);
                JwtIssuerProperties properties = context.getBean(JwtIssuerProperties.class);
                assertThat(properties.getIssuer()).isEqualTo("auth-service");
                assertThat(properties.getAudience()).isEqualTo("auth-platform-client");
                assertThat(properties.getAccessTokenExpiryMinutes()).isEqualTo(15L);
                assertThat(properties.getRefreshTokenExpiryMinutes()).isEqualTo(43200L);
            });
    }

    @Test
    void startupFailsWhenIssuerIsBlank() {
        contextRunner
            .withPropertyValues("auth-platform.issuer.issuer=", AUDIENCE, ACCESS_EXPIRY, REFRESH_EXPIRY)
            .run(context -> {
                assertThat(context).hasFailed();
                assertThat(context.getStartupFailure())
                    .hasStackTraceContaining("'issuer'")
                    .hasStackTraceContaining("must not be blank");
            });
    }

    @Test
    void startupFailsWhenIssuerIsAbsentEntirely() {
        contextRunner
            .withPropertyValues(AUDIENCE, ACCESS_EXPIRY, REFRESH_EXPIRY)
            .run(context -> {
                assertThat(context).hasFailed();
                assertThat(context.getStartupFailure())
                    .hasStackTraceContaining("'issuer'")
                    .hasStackTraceContaining("must not be blank");
            });
    }

    @Test
    void startupFailsWhenAudienceIsBlank() {
        contextRunner
            .withPropertyValues(ISSUER, "auth-platform.issuer.audience=", ACCESS_EXPIRY, REFRESH_EXPIRY)
            .run(context -> {
                assertThat(context).hasFailed();
                assertThat(context.getStartupFailure())
                    .hasStackTraceContaining("'audience'")
                    .hasStackTraceContaining("must not be blank");
            });
    }

    @Test
    void startupFailsWhenAccessTokenExpiryIsZero() {
        contextRunner
            .withPropertyValues(ISSUER, AUDIENCE, "auth-platform.issuer.access-token-expiry-minutes=0", REFRESH_EXPIRY)
            .run(context -> {
                assertThat(context).hasFailed();
                assertThat(context.getStartupFailure())
                    .hasStackTraceContaining("'accessTokenExpiryMinutes'")
                    .hasStackTraceContaining("must be greater than 0");
            });
    }

    /**
     * The exact scenario that used to mint instantly-dead tokens behind a green startup: the
     * property is simply not there, so the primitive {@code long} binds to {@code 0}.
     */
    @Test
    void startupFailsWhenAccessTokenExpiryIsAbsentEntirely() {
        contextRunner
            .withPropertyValues(ISSUER, AUDIENCE, REFRESH_EXPIRY)
            .run(context -> {
                assertThat(context).hasFailed();
                assertThat(context.getStartupFailure())
                    .hasStackTraceContaining("'accessTokenExpiryMinutes'")
                    .hasStackTraceContaining("must be greater than 0");
            });
    }

    @Test
    void startupFailsWhenRefreshTokenExpiryIsAbsentEntirely() {
        contextRunner
            .withPropertyValues(ISSUER, AUDIENCE, ACCESS_EXPIRY)
            .run(context -> {
                assertThat(context).hasFailed();
                assertThat(context.getStartupFailure())
                    .hasStackTraceContaining("'refreshTokenExpiryMinutes'")
                    .hasStackTraceContaining("must be greater than 0");
            });
    }

    @Test
    void startupFailsWhenRefreshTokenExpiryIsNegative() {
        contextRunner
            .withPropertyValues(ISSUER, AUDIENCE, ACCESS_EXPIRY,
                "auth-platform.issuer.refresh-token-expiry-minutes=-1")
            .run(context -> {
                assertThat(context).hasFailed();
                assertThat(context.getStartupFailure())
                    .hasStackTraceContaining("'refreshTokenExpiryMinutes'")
                    .hasStackTraceContaining("must be greater than 0");
            });
    }

    @Configuration
    @EnableConfigurationProperties(JwtIssuerProperties.class)
    static class JwtIssuerPropertiesTestConfig {
    }
}
