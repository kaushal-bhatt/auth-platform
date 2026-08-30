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
     * Skip the limit for requests that did not arrive through the trusted reverse proxy.
     * <p>
     * The limit exists to throttle the public demo, and its counter is keyed on client IP alone -
     * not on IP and path. Server-to-server callers on the internal network therefore all collapse
     * into a single bucket: every request the portfolio makes to {@code /auth/refresh} on behalf of
     * every admin session shares one allowance of {@link #getMaxRequests()}. With a 15-minute
     * access token that is four refreshes an hour, so a day's worth of ordinary admin work
     * exhausts the whole window and the admin is then forced to sign in again every 15 minutes
     * until it resets. That is the demo's throttle punishing the one caller it was never aimed at.
     * <p>
     * Absence of {@code X-Real-IP} is what identifies such a caller, and it is a sound signal
     * precisely because of the deployment topology: the app container publishes no host port
     * ({@code expose}, not {@code ports}), so the only route in from the internet is the proxy, and
     * the proxy sets that header with {@code header_up} on every request it forwards. A caller who
     * reaches this service without it is by construction already inside the network.
     * <p>
     * That reasoning depends entirely on the topology, so this is a switch rather than an
     * assumption: set it {@code false} anywhere the service is reachable directly, where the
     * absence of a header proves nothing and this would hand every client a way to opt out of the
     * limit. It is ignored unless {@link #isTrustForwardedFor()} is also true, since that flag is
     * the existing statement that a trusted proxy is in front.
     */
    private boolean exemptUnproxiedRequests = true;

    /**
     * Ant-style path patterns whose requests count against the limit. Defaults to the demo's
     * state-changing auth actions; the always-public bootstrap reads (JWKS) and the demo page's own
     * static assets are intentionally never limited.
     */
    private List<String> limitedPaths = List.of(
        "/auth/register",
        "/auth/login",
        "/auth/refresh",
        // Reachable from the internet and authenticated only by the client secret, so without a
        // limit an attacker may guess that secret as fast as the network allows. It does not
        // change the demo-run arithmetic on maxRequests above: a visitor never calls this, only
        // the portfolio's server does, and that caller is exempt under exemptUnproxiedRequests.
        "/sso/token",
        "/passkey/register/init",
        "/passkey/register/complete",
        "/passkey/login/init",
        "/passkey/login/complete"
    );
}
