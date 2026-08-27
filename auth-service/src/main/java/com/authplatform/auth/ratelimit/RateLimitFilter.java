package com.authplatform.auth.ratelimit;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Fixed-window, per-client-IP rate limiter for the public demo deployment. Counts only the
 * state-changing auth actions named in {@link RateLimitProperties#getLimitedPaths()} and, once a
 * client exceeds {@link RateLimitProperties#getMaxRequests()} within
 * {@link RateLimitProperties#getWindowHours()}, answers those requests with {@code 429} until the
 * client's window rolls over.
 * <p>
 * <b>Scope and honesty:</b> this is a demo abuse guard, not a security feature. The counters live
 * in an in-memory map, so they are per-instance and reset on restart - fine for a single free-tier
 * instance, and deliberately not a distributed/durable limiter. It does not close the
 * account-lockout or login-throttling gaps the README documents; it only stops a public showcase
 * from being trivially hammered. Reads that must always work to bootstrap a verifier (the JWKS
 * endpoint) and the demo page's own static assets are never limited.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
@EnableConfigurationProperties(RateLimitProperties.class)
public class RateLimitFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(RateLimitFilter.class);

    private final RateLimitProperties properties;
    private final AntPathMatcher pathMatcher = new AntPathMatcher();
    private final Map<String, Window> counters = new ConcurrentHashMap<>();

    public RateLimitFilter(RateLimitProperties properties) {
        this.properties = properties;
    }

    /**
     * One client's fixed window: the epoch-millis at which the window opened, plus a live count.
     * A single mutable object per key keeps the whole check-and-increment lock-free via
     * {@link ConcurrentHashMap#compute}.
     */
    private static final class Window {
        long windowStartMillis;
        final AtomicInteger count = new AtomicInteger(0);

        Window(long windowStartMillis) {
            this.windowStartMillis = windowStartMillis;
        }
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        if (!properties.isEnabled()) {
            return true;
        }
        // Preflight requests carry no credentials and never mutate state; counting them would let
        // the browser's own CORS machinery burn a client's allowance before any real action.
        if ("OPTIONS".equalsIgnoreCase(request.getMethod())) {
            return true;
        }
        String path = request.getRequestURI();
        return properties.getLimitedPaths().stream().noneMatch(pattern -> pathMatcher.match(pattern, path));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        String clientKey = resolveClientKey(request);
        long windowMillis = Duration.ofHours(properties.getWindowHours()).toMillis();
        long now = System.currentTimeMillis();

        Window window = counters.compute(clientKey, (key, existing) -> {
            if (existing == null || now - existing.windowStartMillis >= windowMillis) {
                Window fresh = new Window(now);
                fresh.count.incrementAndGet();
                return fresh;
            }
            existing.count.incrementAndGet();
            return existing;
        });

        int used = window.count.get();
        int max = properties.getMaxRequests();
        long resetAtMillis = window.windowStartMillis + windowMillis;
        int remaining = Math.max(0, max - used);

        response.setHeader("X-RateLimit-Limit", Integer.toString(max));
        response.setHeader("X-RateLimit-Remaining", Integer.toString(remaining));
        response.setHeader("X-RateLimit-Reset", Long.toString(resetAtMillis / 1000L));

        if (used > max) {
            long retryAfterSeconds = Math.max(1, (resetAtMillis - now) / 1000L);
            writeTooManyRequests(response, retryAfterSeconds);
            return;
        }

        // Opportunistically evict stale windows so the map cannot grow without bound over a long
        // uptime. Cheap and only runs occasionally.
        if (counters.size() > 10_000) {
            counters.entrySet().removeIf(e -> now - e.getValue().windowStartMillis >= windowMillis);
        }

        chain.doFilter(request, response);
    }

    /**
     * The client's identity for limiting purposes. Behind a single trusted reverse proxy the real
     * client IP is the first entry of {@code X-Forwarded-For}; otherwise the socket peer address is
     * used. {@code X-Forwarded-For} can list several hops ({@code client, proxy1, proxy2}); the
     * left-most is the originating client.
     */
    private String resolveClientKey(HttpServletRequest request) {
        if (properties.isTrustForwardedFor()) {
            String forwarded = request.getHeader("X-Forwarded-For");
            if (forwarded != null && !forwarded.isBlank()) {
                int comma = forwarded.indexOf(',');
                return (comma >= 0 ? forwarded.substring(0, comma) : forwarded).trim();
            }
        }
        return request.getRemoteAddr();
    }

    private void writeTooManyRequests(HttpServletResponse response, long retryAfterSeconds) throws IOException {
        log.debug("rate limit exceeded; responding 429, retry after {}s", retryAfterSeconds);
        response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
        response.setHeader(HttpHeaders.RETRY_AFTER, Long.toString(retryAfterSeconds));
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        long retryAfterHours = Math.max(1, retryAfterSeconds / 3600);
        response.getWriter().write(
            "{\"error\":\"rate_limited\",\"message\":\"Demo limit reached: "
                + properties.getMaxRequests()
                + " actions per day from your network. Try again in about "
                + retryAfterHours + " hour" + (retryAfterHours == 1 ? "" : "s")
                + ".\",\"retryAfterSeconds\":" + retryAfterSeconds + "}");
    }
}
