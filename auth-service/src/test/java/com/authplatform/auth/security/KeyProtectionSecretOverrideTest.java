package com.authplatform.auth.security;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

import java.security.SecureRandom;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies the Fix 1 override mechanism actually works, rather than assuming it does.
 * <p>
 * {@code application.yml} declares:
 * <pre>key-protection-secret: ${AUTH_PLATFORM_ISSUER_KEY_PROTECTION_SECRET:}</pre>
 * This test reproduces that exact placeholder expression against an
 * {@link ApplicationContextRunner}, supplying (or withholding) a property named
 * {@code AUTH_PLATFORM_ISSUER_KEY_PROTECTION_SECRET} — the same name Spring's relaxed
 * binding uses for an OS environment variable of that name — to prove: (1) when the
 * variable is present, it takes precedence and a {@link KeyProtector} bean is created,
 * and (2) when it is absent, the placeholder resolves to the empty default and the
 * blank check trips, failing the context.
 */
class KeyProtectionSecretOverrideTest {

    private static final String PLACEHOLDER_PROPERTY =
        "auth-platform.issuer.key-protection-secret=${AUTH_PLATFORM_ISSUER_KEY_PROTECTION_SECRET:}";

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
        .withUserConfiguration(KeyProtectorTestConfig.class);

    @Test
    void environmentVariableOverrideTakesPrecedenceAndKeyProtectorBeanIsCreated() {
        byte[] secretBytes = new byte[32];
        new SecureRandom().nextBytes(secretBytes);
        String secret = Base64.getEncoder().encodeToString(secretBytes);

        contextRunner
            .withPropertyValues(
                "AUTH_PLATFORM_ISSUER_KEY_PROTECTION_SECRET=" + secret,
                PLACEHOLDER_PROPERTY)
            .run(context -> assertThat(context).hasSingleBean(KeyProtector.class));
    }

    @Test
    void startupFailsWhenEnvironmentVariableIsAbsentAndPlaceholderFallsBackToBlankDefault() {
        contextRunner
            .withPropertyValues(PLACEHOLDER_PROPERTY)
            .run(context -> {
                assertThat(context).hasFailed();
                assertThat(context.getStartupFailure())
                    .rootCause()
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("auth-platform.issuer.key-protection-secret");
            });
    }

    @Configuration
    @Import(KeyProtector.class)
    static class KeyProtectorTestConfig {
    }
}
