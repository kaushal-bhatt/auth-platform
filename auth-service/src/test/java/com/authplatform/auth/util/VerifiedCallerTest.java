package com.authplatform.auth.util;

import com.authplatform.auth.exception.CustomException;
import com.authplatform.jwt.interceptor.JwtAuthenticationInterceptor;
import com.authplatform.jwt.model.JwtClaims;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class VerifiedCallerTest {

    @Test
    void returnsTheNumericSubjectOfTheVerifiedClaims() {
        MockHttpServletRequest request = requestWithSubject("77");

        assertThat(VerifiedCaller.requireUserId(request)).isEqualTo(77L);
    }

    /**
     * The reason this class exists: {@code sub} is a free-form string in a JWT, so a
     * signature-valid token can carry a non-numeric subject, and a bare
     * {@code Long.valueOf(claims.userId())} made that an HTTP 500 with a stack trace.
     */
    @Test
    void rejectsANonNumericSubjectAsUnauthorized() {
        for (String subject : new String[]{"not-a-number", "", "  ", "9999999999999999999999", "1.5", "+7 "}) {
            MockHttpServletRequest request = requestWithSubject(subject);

            assertThatThrownBy(() -> VerifiedCaller.requireUserId(request))
                .isInstanceOf(CustomException.class)
                .hasMessage("unauthorized")
                .extracting(e -> ((CustomException) e).getStatus())
                .isEqualTo(401);
        }
    }

    @Test
    void rejectsAMissingSubjectAsUnauthorized() {
        assertThatThrownBy(() -> VerifiedCaller.requireUserId(requestWithSubject(null)))
            .isInstanceOf(CustomException.class)
            .extracting(e -> ((CustomException) e).getStatus())
            .isEqualTo(401);
    }

    /**
     * Defence in depth: the interceptor always sets the attribute before a protected handler runs,
     * so absent claims mean something is wired wrong - which must fail closed, not with a
     * {@link NullPointerException} turned 500.
     */
    @Test
    void rejectsAbsentClaimsAsUnauthorized() {
        assertThatThrownBy(() -> VerifiedCaller.requireUserId(new MockHttpServletRequest()))
            .isInstanceOf(CustomException.class)
            .extracting(e -> ((CustomException) e).getStatus())
            .isEqualTo(401);
    }

    private static MockHttpServletRequest requestWithSubject(String subject) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setAttribute(JwtAuthenticationInterceptor.CLAIMS_ATTRIBUTE, new JwtClaims(
            subject, "someone@example.com", "auth-service", "auth-platform-client",
            "session", Instant.EPOCH, Instant.EPOCH.plusSeconds(900)));
        return request;
    }
}
