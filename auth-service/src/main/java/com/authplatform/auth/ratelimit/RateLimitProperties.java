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
 * variable {@code AUTH_PLATFORM_RATE_LIMIT_ENABLED=true}). This exists to stop a public showcase
 * deployment from being hammered - it is a demo guard rail, not a security control, and is not a
 * substitute for the real per-account lockout/throttling gaps documented in the README.
 */
@Getter
@Setter
@ConfigurationProperties(prefix = "auth-platform.rate-limit")
public class RateLimitProperties {

    /** Master switch. Off unless a deployment sets it. */
    private boolean enabled = false;

    /**
     * How many limited requests one client key may make per window before receiving 429.
     * <p>
     * This counts requests, not visitors, so the default is expressed in units of demo runs: one
     * full run costs six limited requests (register, login, and an init and a complete for each of
     * the two WebAuthn ceremonies), and 30 is five such runs. A value below six is a trap rather
     * than a strict setting - it lets nobody finish the demo even once, because the last request of
     * the passkey login is the sixth and is refused. Keep this in step with
     * {@link #getLimitedPaths()} if that list changes.
     */
    private int maxRequests = 30;

    /** Length of the fixed window, in hours, after which a client's counter resets. */
    private long windowHours = 24;

    /**
     * Trust the reverse proxy's client-IP headers ({@code X-Real-IP}, then the right-most entry of
     * {@code X-Forwarded-For}) instead of the socket peer address. Correct when the service sits
     * behind a trusted proxy that sets them - the topology in {@code deploy/DEPLOY.md}. Set this
     * {@code false} if the service is ever exposed directly to clients, where both headers are
     * attacker-supplied and keying on them would let anyone mint a new identity per request.
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
