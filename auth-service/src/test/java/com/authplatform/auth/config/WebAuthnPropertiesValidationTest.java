package com.authplatform.auth.config;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Proves {@link WebAuthnProperties} genuinely fails startup - with a message naming the offending
 * property - when any of its three settings is missing or blank, mirroring
 * {@code JwtIssuerPropertiesValidationTest}.
 * <p>
 * This is load-bearing, not defensive theatre: without {@code @Validated}, a blank
 * {@code relying-party-id} or {@code origin} would bind to an empty string, startup would stay
 * green, and every WebAuthn ceremony would fail deep inside webauthn4j's validator (a confusing
 * {@code ValidationException}/{@code NullPointerException}) instead of failing fast at startup
 * with a message naming the actual misconfiguration.
 */
class WebAuthnPropertiesValidationTest {

    private static final String RP_ID = "auth-platform.webauthn.relying-party-id=localhost";
    private static final String RP_NAME = "auth-platform.webauthn.relying-party-name=Auth Platform";
    private static final String ORIGIN = "auth-platform.webauthn.origin=http://localhost:3000";

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
        .withUserConfiguration(WebAuthnPropertiesTestConfig.class);

    @Test
    void bindsSuccessfullyWhenEveryPropertyIsPresentAndValid() {
        contextRunner
            .withPropertyValues(RP_ID, RP_NAME, ORIGIN)
            .run(context -> {
                assertThat(context).hasSingleBean(WebAuthnProperties.class);
                WebAuthnProperties properties = context.getBean(WebAuthnProperties.class);
                assertThat(properties.getRelyingPartyId()).isEqualTo("localhost");
                assertThat(properties.getRelyingPartyName()).isEqualTo("Auth Platform");
                assertThat(properties.getOrigin()).isEqualTo("http://localhost:3000");
            });
    }

    @Test
    void startupFailsWhenRelyingPartyIdIsBlank() {
        contextRunner
            .withPropertyValues("auth-platform.webauthn.relying-party-id=", RP_NAME, ORIGIN)
            .run(context -> {
                assertThat(context).hasFailed();
                assertThat(context.getStartupFailure())
                    .hasStackTraceContaining("'relyingPartyId'")
                    .hasStackTraceContaining("must not be blank");
            });
    }

    @Test
    void startupFailsWhenRelyingPartyIdIsAbsentEntirely() {
        contextRunner
            .withPropertyValues(RP_NAME, ORIGIN)
            .run(context -> {
                assertThat(context).hasFailed();
                assertThat(context.getStartupFailure())
                    .hasStackTraceContaining("'relyingPartyId'")
                    .hasStackTraceContaining("must not be blank");
            });
    }

    @Test
    void startupFailsWhenRelyingPartyNameIsBlank() {
        contextRunner
            .withPropertyValues(RP_ID, "auth-platform.webauthn.relying-party-name=", ORIGIN)
            .run(context -> {
                assertThat(context).hasFailed();
                assertThat(context.getStartupFailure())
                    .hasStackTraceContaining("'relyingPartyName'")
                    .hasStackTraceContaining("must not be blank");
            });
    }

    @Test
    void startupFailsWhenOriginIsBlank() {
        contextRunner
            .withPropertyValues(RP_ID, RP_NAME, "auth-platform.webauthn.origin=")
            .run(context -> {
                assertThat(context).hasFailed();
                assertThat(context.getStartupFailure())
                    .hasStackTraceContaining("'origin'")
                    .hasStackTraceContaining("must not be blank");
            });
    }

    @Test
    void startupFailsWhenOriginIsAbsentEntirely() {
        contextRunner
            .withPropertyValues(RP_ID, RP_NAME)
            .run(context -> {
                assertThat(context).hasFailed();
                assertThat(context.getStartupFailure())
                    .hasStackTraceContaining("'origin'")
                    .hasStackTraceContaining("must not be blank");
            });
    }

    @Configuration
    @EnableConfigurationProperties(WebAuthnProperties.class)
    static class WebAuthnPropertiesTestConfig {
    }
}
