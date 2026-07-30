package com.authplatform.auth.util;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Locale;

import static org.assertj.core.api.Assertions.assertThat;

class EmailNormalizerTest {

    private Locale originalDefaultLocale;

    @BeforeEach
    void captureDefaultLocale() {
        originalDefaultLocale = Locale.getDefault();
    }

    @AfterEach
    void restoreDefaultLocale() {
        Locale.setDefault(originalDefaultLocale);
    }

    @Test
    void trimsSurroundingWhitespace() {
        assertThat(EmailNormalizer.normalize("  alice@x.com  ")).isEqualTo("alice@x.com");
    }

    @Test
    void lowerCasesEmail() {
        assertThat(EmailNormalizer.normalize("Alice@X.com")).isEqualTo("alice@x.com");
    }

    @Test
    void returnsNullForNullInput() {
        assertThat(EmailNormalizer.normalize(null)).isNull();
    }

    /**
     * Pins the {@link Locale#ROOT} requirement: under a Turkish default locale,
     * {@code "I".toLowerCase()} produces a dotless "ı" instead of ASCII "i", which would
     * corrupt this email address. Forcing the JVM default locale to Turkish here reproduces
     * that failure mode if {@link EmailNormalizer} ever regresses to {@code toLowerCase()}
     * without an explicit {@link Locale#ROOT}.
     */
    @Test
    void upperCaseINormalisesToAsciiIRegardlessOfDefaultLocale() {
        Locale.setDefault(Locale.of("tr", "TR"));

        assertThat(EmailNormalizer.normalize("IAN@EXAMPLE.COM")).isEqualTo("ian@example.com");
    }
}
