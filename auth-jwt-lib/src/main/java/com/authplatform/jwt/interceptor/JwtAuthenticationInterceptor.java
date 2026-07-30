package com.authplatform.jwt.interceptor;

import com.authplatform.jwt.annotation.JwtTokenVerification;
import com.authplatform.jwt.model.JwtVerificationResult;
import com.authplatform.jwt.service.JwtVerificationService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationInterceptor implements HandlerInterceptor {

    public static final String CLAIMS_ATTRIBUTE = "jwtClaims";

    /**
     * fixed, generic reason sent to the client on any authentication failure. the specific
     * reason - which may embed attacker influenced text such as a sanitized key id, algorithm
     * name, or issuer - must never be reflected into the response body; it is only logged
     * server side.
     */
    private static final String GENERIC_UNAUTHORIZED_MESSAGE = "unauthorized";

    private final JwtVerificationService jwtVerificationService;

    /**
     * lowercase-normalized bearer scheme prefix, per RFC 6750 the auth-scheme token is
     * case-insensitive. matching is done against a lowercased copy of the header value.
     */
    private static final String BEARER_PREFIX = "bearer";

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        if (!(handler instanceof HandlerMethod handlerMethod)) {
            return true;
        }
        JwtTokenVerification annotation = AnnotatedElementUtils.findMergedAnnotation(
            handlerMethod.getMethod(), JwtTokenVerification.class);
        if (annotation == null) {
            annotation = AnnotatedElementUtils.findMergedAnnotation(
                handlerMethod.getBeanType(), JwtTokenVerification.class);
        }
        if (annotation == null) {
            return true;
        }

        String token = extractBearerToken(request.getHeader("Authorization"));
        if (token == null || token.isBlank()) {
            log.debug("rejecting request: missing bearer token");
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, GENERIC_UNAUTHORIZED_MESSAGE);
            return false;
        }

        JwtVerificationResult result = jwtVerificationService.verify(token);
        if (!result.valid()) {
            log.debug("rejecting request: jwt verification failed: {}", result.errorMessage());
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, GENERIC_UNAUTHORIZED_MESSAGE);
            return false;
        }

        if (result.claims() == null) {
            log.warn("rejecting request: jwt verification service returned a valid result with null "
                + "claims; this indicates a broken JwtVerificationService implementation");
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, GENERIC_UNAUTHORIZED_MESSAGE);
            return false;
        }

        request.setAttribute(CLAIMS_ATTRIBUTE, result.claims());
        return true;
    }

    /**
     * extracts the bearer token from an {@code Authorization} header, matching the
     * {@code Bearer} auth-scheme case-insensitively per RFC 6750 and tolerating incidental
     * whitespace between the scheme and the token. returns {@code null} when the header is
     * absent or does not use the bearer scheme; returns a blank string when the scheme is
     * present but no token follows, which the caller must still reject.
     */
    private static String extractBearerToken(String header) {
        if (header == null) {
            return null;
        }
        String trimmed = header.stripLeading();
        if (trimmed.length() < BEARER_PREFIX.length()
            || !trimmed.regionMatches(true, 0, BEARER_PREFIX, 0, BEARER_PREFIX.length())) {
            return null;
        }
        String remainder = trimmed.substring(BEARER_PREFIX.length());
        if (!remainder.isEmpty() && !Character.isWhitespace(remainder.charAt(0))) {
            // e.g. "bearertoken" or "bearerish" - the scheme token doesn't actually match
            return null;
        }
        return remainder.stripLeading();
    }
}
