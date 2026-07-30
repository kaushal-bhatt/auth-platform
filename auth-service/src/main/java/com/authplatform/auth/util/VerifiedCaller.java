package com.authplatform.auth.util;

import com.authplatform.auth.exception.CustomException;
import com.authplatform.jwt.interceptor.JwtAuthenticationInterceptor;
import com.authplatform.jwt.model.JwtClaims;
import jakarta.servlet.http.HttpServletRequest;

/**
 * Reads the acting user's id off the verified {@link JwtClaims} that auth-jwt-lib's
 * {@link JwtAuthenticationInterceptor} placed on the request.
 * <p>
 * Shared by every {@code @JwtTokenVerification}-protected controller so the conversion is done one
 * way in one place. Each controller previously did a bare {@code Long.valueOf(claims.userId())},
 * which is a 500 for anything this service's own {@code JwtIssuer} would not have produced: the
 * {@code sub} claim is a free-form string in a JWT (RFC 7519 §4.1.2), so a signature-valid token
 * from the configured issuer carrying a non-numeric {@code sub} - a uuid, an email, anything -
 * threw {@link NumberFormatException} past the controller into
 * {@code GlobalExceptionHandler}'s catch-all as HTTP 500 with a full stack trace at ERROR level.
 * <p>
 * A token whose subject is not one of this service's user ids does not identify a caller here, so
 * the correct answer is 401, with the same fixed message
 * {@link JwtAuthenticationInterceptor} itself uses for a rejected token. The offending value is
 * never logged or echoed.
 */
public final class VerifiedCaller {

    private static final String UNAUTHORIZED = "unauthorized";

    private VerifiedCaller() {
    }

    /**
     * @param request the current request, already past {@link JwtAuthenticationInterceptor}
     * @return the verified caller's numeric user id
     * @throws CustomException 401 if the claims are absent, or the {@code sub} claim is missing or
     *                         is not a valid {@code long}
     */
    public static Long requireUserId(HttpServletRequest request) {
        JwtClaims claims = (JwtClaims) request.getAttribute(JwtAuthenticationInterceptor.CLAIMS_ATTRIBUTE);
        if (claims == null || claims.userId() == null) {
            throw new CustomException(401, UNAUTHORIZED);
        }
        try {
            return Long.valueOf(claims.userId());
        } catch (NumberFormatException e) {
            throw new CustomException(401, UNAUTHORIZED);
        }
    }
}
