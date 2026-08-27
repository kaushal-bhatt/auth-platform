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
 * unless enabled, it only counts configured paths, it keys on the client IP, and it flips to 429
 * strictly after the configured allowance.
 */
class RateLimitFilterTest {

    private RateLimitProperties props(boolean enabled, int max) {
        RateLimitProperties p = new RateLimitProperties();
        p.setEnabled(enabled);
        p.setMaxRequests(max);
        p.setWindowHours(24);
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
    void trustsFirstHopOfForwardedForHeader() throws Exception {
        RateLimitFilter filter = new RateLimitFilter(props(true, 1));
        MockHttpServletRequest first = post("/auth/login", "10.0.0.1"); // proxy socket addr
        first.addHeader("X-Forwarded-For", "203.0.113.7, 10.0.0.1");
        assertThat(run(filter, first)).isEqualTo(HttpServletResponse.SC_OK);

        // Same real client (first hop), different proxy socket address: must still be limited.
        MockHttpServletRequest second = post("/auth/login", "10.0.0.2");
        second.addHeader("X-Forwarded-For", "203.0.113.7, 10.0.0.2");
        assertThat(run(filter, second)).isEqualTo(429);
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
