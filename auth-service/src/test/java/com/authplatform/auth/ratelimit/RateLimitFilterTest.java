package com.authplatform.auth.ratelimit;

import static org.assertj.core.api.Assertions.assertThat;

import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

/**
 * Unit tests for {@link RateLimitFilter}, driven with Spring's mock servlet objects so no web
 * server, database, or Docker is involved. These pin the demo guard-rail's contract: it is off
 * unless enabled, it only counts configured paths, it keys on the client IP, it flips to 429
 * strictly after the configured allowance, and it lets through callers that reached the service
 * without passing the trusted proxy - but only where a trusted proxy is declared to exist.
 */
class RateLimitFilterTest {

    private RateLimitProperties props(boolean enabled, int max) {
        RateLimitProperties p = new RateLimitProperties();
        p.setEnabled(enabled);
        p.setMaxRequests(max);
        p.setWindowHours(24);
        // The tests below are about counting and about which value the counter is keyed on, and
        // they build requests the way a client reaches the socket rather than the way the proxy
        // forwards one - no X-Real-IP. That is exactly what the exemption keys on, so leaving it
        // at its default would exempt nearly every request here and quietly turn these into
        // assertions that nothing is ever limited. The exemption has its own tests instead.
        p.setExemptUnproxiedRequests(false);
        return p;
    }

    /** As {@link #props(boolean, int)}, but with the unproxied-caller exemption left switched on. */
    private RateLimitProperties propsWithExemption(int max) {
        RateLimitProperties p = props(true, max);
        p.setExemptUnproxiedRequests(true);
        return p;
    }

    private MockHttpServletRequest post(String uri, String ip) {
        MockHttpServletRequest req = new MockHttpServletRequest("POST", uri);
        req.setRemoteAddr(ip);
        return req;
    }

    private int run(RateLimitFilter filter, MockHttpServletRequest req) throws Exception {
        MockHttpServletResponse res = new MockHttpServletResponse();
        filter.doFilter(req, res, new MockFilterChain());
        return res.getStatus();
    }

    @Test
    void disabledByDefault_passesEverythingThrough() throws Exception {
        RateLimitFilter filter = new RateLimitFilter(props(false, 1));
        for (int i = 0; i < 10; i++) {
            assertThat(run(filter, post("/auth/login", "1.1.1.1"))).isEqualTo(HttpServletResponse.SC_OK);
        }
    }

    @Test
    void allowsUpToMaxThenReturns429() throws Exception {
        RateLimitFilter filter = new RateLimitFilter(props(true, 5));
        for (int i = 0; i < 5; i++) {
            assertThat(run(filter, post("/auth/login", "9.9.9.9")))
                .as("request %d within allowance", i + 1)
                .isEqualTo(HttpServletResponse.SC_OK);
        }
        assertThat(run(filter, post("/auth/login", "9.9.9.9"))).isEqualTo(429);
        assertThat(run(filter, post("/auth/login", "9.9.9.9"))).isEqualTo(429);
    }

    @Test
    void countsAreIsolatedPerClientIp() throws Exception {
        RateLimitFilter filter = new RateLimitFilter(props(true, 1));
        assertThat(run(filter, post("/auth/login", "2.2.2.2"))).isEqualTo(HttpServletResponse.SC_OK);
        assertThat(run(filter, post("/auth/login", "2.2.2.2"))).isEqualTo(429);
        // A different client still has its full allowance.
        assertThat(run(filter, post("/auth/login", "3.3.3.3"))).isEqualTo(HttpServletResponse.SC_OK);
    }

    @Test
    void unlimitedPathsAreNeverCounted() throws Exception {
        RateLimitFilter filter = new RateLimitFilter(props(true, 1));
        for (int i = 0; i < 20; i++) {
            assertThat(run(filter, post("/.well-known/jwks.json", "4.4.4.4"))).isEqualTo(HttpServletResponse.SC_OK);
        }
        // The limited path still has its own independent, intact allowance.
        assertThat(run(filter, post("/auth/register", "4.4.4.4"))).isEqualTo(HttpServletResponse.SC_OK);
        assertThat(run(filter, post("/auth/register", "4.4.4.4"))).isEqualTo(429);
    }

    @Test
    void prefersRealIpOverAnythingTheCallerCanForge() throws Exception {
        RateLimitFilter filter = new RateLimitFilter(props(true, 1));
        // The proxy APPENDS to X-Forwarded-For, so its left-most entries are whatever the caller
        // sent. X-Real-IP is written with an overwrite, so it is the one value a caller cannot
        // influence - and changing the forged entries must not buy a fresh allowance.
        MockHttpServletRequest first = post("/auth/login", "10.0.0.1");
        first.addHeader("X-Real-IP", "203.0.113.7");
        first.addHeader("X-Forwarded-For", "1.1.1.1, 203.0.113.7, 10.0.0.1");
        assertThat(run(filter, first)).isEqualTo(HttpServletResponse.SC_OK);

        MockHttpServletRequest second = post("/auth/login", "10.0.0.1");
        second.addHeader("X-Real-IP", "203.0.113.7");
        second.addHeader("X-Forwarded-For", "2.2.2.2, 203.0.113.7, 10.0.0.1");
        assertThat(run(filter, second)).isEqualTo(429);
    }

    @Test
    void withoutRealIpTrustsTheLastHopOfForwardedFor() throws Exception {
        RateLimitFilter filter = new RateLimitFilter(props(true, 1));
        // No X-Real-IP: the right-most entry is the hop the nearest trusted proxy wrote. Keying on
        // the left-most one would let a forged value per request dodge the limit entirely.
        MockHttpServletRequest first = post("/auth/login", "10.0.0.1");
        first.addHeader("X-Forwarded-For", "1.1.1.1, 203.0.113.7");
        assertThat(run(filter, first)).isEqualTo(HttpServletResponse.SC_OK);

        MockHttpServletRequest second = post("/auth/login", "10.0.0.1");
        second.addHeader("X-Forwarded-For", "2.2.2.2, 203.0.113.7");
        assertThat(run(filter, second)).isEqualTo(429);
    }

    @Test
    void ssoTokenExchangeIsLimited() throws Exception {
        // Reachable from the internet and guarded only by the client secret, so an unlimited
        // endpoint here is an unlimited number of guesses at that secret.
        RateLimitFilter filter = new RateLimitFilter(props(true, 1));
        assertThat(run(filter, post("/sso/token", "6.6.6.6"))).isEqualTo(HttpServletResponse.SC_OK);
        assertThat(run(filter, post("/sso/token", "6.6.6.6"))).isEqualTo(429);
    }

    @Test
    void callersThatDidNotComeThroughTheProxyAreExempt() throws Exception {
        // The portfolio reaching auth-service directly over the internal network. Without this it
        // shares one allowance across every admin session, and a day of ordinary admin work spends
        // the whole window on token refreshes.
        RateLimitFilter filter = new RateLimitFilter(propsWithExemption(1));
        for (int i = 0; i < 10; i++) {
            assertThat(run(filter, post("/auth/refresh", "172.18.0.5")))
                .as("internal request %d", i + 1)
                .isEqualTo(HttpServletResponse.SC_OK);
        }
    }

    @Test
    void exemptionDoesNotReachCallersArrivingThroughTheProxy() throws Exception {
        RateLimitFilter filter = new RateLimitFilter(propsWithExemption(1));
        MockHttpServletRequest first = post("/auth/login", "10.0.0.1");
        first.addHeader("X-Real-IP", "203.0.113.7");
        assertThat(run(filter, first)).isEqualTo(HttpServletResponse.SC_OK);

        MockHttpServletRequest second = post("/auth/login", "10.0.0.1");
        second.addHeader("X-Real-IP", "203.0.113.7");
        assertThat(run(filter, second)).isEqualTo(429);
    }

    @Test
    void exemptionIsInertWhenNoProxyIsTrusted() throws Exception {
        // Without a trusted proxy in front, a missing X-Real-IP proves nothing - every caller
        // arrives without one. Honouring the exemption there would switch the limiter off for
        // everybody, so it must stay dormant.
        RateLimitProperties p = propsWithExemption(1);
        p.setTrustForwardedFor(false);
        RateLimitFilter filter = new RateLimitFilter(p);

        assertThat(run(filter, post("/auth/login", "7.7.7.7"))).isEqualTo(HttpServletResponse.SC_OK);
        assertThat(run(filter, post("/auth/login", "7.7.7.7"))).isEqualTo(429);
    }

    @Test
    void setsRemainingHeader() throws Exception {
        RateLimitFilter filter = new RateLimitFilter(props(true, 5));
        MockHttpServletResponse res = new MockHttpServletResponse();
        filter.doFilter(post("/auth/login", "5.5.5.5"), res, new MockFilterChain());
        assertThat(res.getHeader("X-RateLimit-Limit")).isEqualTo("5");
        assertThat(res.getHeader("X-RateLimit-Remaining")).isEqualTo("4");
    }
}
