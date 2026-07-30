package com.authplatform.auth.util;

import java.util.Locale;

/**
 * Normalises email addresses so that every part of the system compares and stores the
 * exact same canonical form.
 *
 * <p><strong>Every future lookup of a user by email MUST go through this helper</strong> -
 * including Task 10's login flow - so that the value checked against the database is always
 * exactly the value that was stored at registration time. Normalising differently on the
 * read side and the write side would make accounts unreachable (e.g. login normalises but
 * registration didn't) or allow duplicate accounts for what a user considers the same email.
 */
public final class EmailNormalizer {

    private EmailNormalizer() {
    }

    /**
     * Trims surrounding whitespace and lower-cases using {@link Locale#ROOT}.
     *
     * <p>{@link Locale#ROOT} is used deliberately instead of the platform/JVM default
     * locale: under a Turkish ({@code tr}) default locale, {@code "I".toLowerCase()}
     * produces a dotless {@code "ı"} rather than ASCII {@code "i"}, which would silently
     * corrupt email addresses containing that letter and break lookups.
     *
     * @param email the raw email address, may be {@code null}
     * @return the trimmed, lower-cased email, or {@code null} if {@code email} is {@code null}
     */
    public static String normalize(String email) {
        if (email == null) {
            return null;
        }
        return email.trim().toLowerCase(Locale.ROOT);
    }
}
