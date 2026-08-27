package com.authplatform.auth.ratelimit;

import java.util.List;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration for the public-demo rate limiter ({@link RateLimitFilter}).
 * <p>
 * Deliberately <b>disabled by default</b>: local development and the whole test suite must behave
 * exactly as before, so nothing is throttled unless a deployment explicitly opts in by setting
 * {@code auth-platform.rate-limit.enabled=true} (in production this is supplied as the environment
 * variable {@code AUTH_PLATFORM_RATELIMIT_ENABLED=true}). This exists to stop a public showcase
 * deployment from being hammered - it is a demo guard rail, not a security control, and is not a
 * substitute for the real per-account lockout/throttling gaps documented in the README.
 */
@Getter
@Setter
@ConfigurationProperties(prefix = "auth-platform.rate-limit")
public class RateLimitProperties {

    /** Master switch. Off unless a deployment sets it. */
    private boolean enabled = false;

    /** How many limited requests one client key may make per window before receiving 429. */
    private int maxRequests = 5;

    /** Length of the fixed window, in hours, after which a client's counter resets. */
    private long windowHours = 24;

    /**
     * Trust the first hop of {@code X-Forwarded-For} for the client IP. Correct when the service
     * sits behind exactly one reverse proxy / load balancer (Caddy, an ALB) that appends the real
     * client IP - which is the deployment topology in {@code deploy/DEPLOY-AWS.md}. If the service
     * were ever exposed directly to clients this should be {@code false}, since a client could then
     * spoof the header to dodge the limit.
     */
    private boolean trustForwardedFor = true;

    /**
     * Ant-style path patterns whose requests count against the limit. Defaults to the demo's
     * state-changing auth actions; the always-public bootstrap reads (JWKS) and the demo page's own
     * static assets are intentionally never limited.
     */
    private List<String> limitedPaths = List.of(
        "/auth/register",
        "/auth/login",
        "/auth/refresh",
        "/passkey/register/init",
        "/passkey/register/complete",
        "/passkey/login/init",
        "/passkey/login/complete"
    );
}
