package com.authplatform.jwt.interceptor;

import com.authplatform.jwt.annotation.JwtTokenVerification;
import com.authplatform.jwt.model.JwtClaims;
import com.authplatform.jwt.model.JwtVerificationResult;
import com.authplatform.jwt.service.JwtVerificationService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.web.method.HandlerMethod;

import java.lang.reflect.Method;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

class JwtAuthenticationInterceptorTest {

    static class ProtectedController {
        @JwtTokenVerification
        public void protectedMethod() {
        }

        public void openMethod() {
        }
    }

    @JwtTokenVerification
    static class ClassAnnotatedController {
        public void openMethod() {
        }
    }

    @JwtTokenVerification
    static class BaseProtectedController {
        public void baseMethod() {
        }
    }

    static class InheritingProtectedController extends BaseProtectedController {
    }

    private final JwtVerificationService jwtVerificationService = mock(JwtVerificationService.class);
    private final JwtAuthenticationInterceptor interceptor = new JwtAuthenticationInterceptor(jwtVerificationService);

    @Test
    void allowsUnannotatedMethodWithoutToken() throws Exception {
        HandlerMethod handlerMethod = handlerMethodFor("openMethod");
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);

        boolean result = interceptor.preHandle(request, response, handlerMethod);

        assertThat(result).isTrue();
        verifyNoInteractions(jwtVerificationService);
    }

    @Test
    void rejectsAnnotatedMethodWithoutBearerHeader() throws Exception {
        HandlerMethod handlerMethod = handlerMethodFor("protectedMethod");
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        when(request.getHeader("Authorization")).thenReturn(null);

        boolean result = interceptor.preHandle(request, response, handlerMethod);

        assertThat(result).isFalse();
        verify(response).sendError(eq(HttpServletResponse.SC_UNAUTHORIZED), anyString());
        verify(request, never()).setAttribute(anyString(), any());
    }

    @Test
    void allowsAnnotatedMethodWithValidToken() throws Exception {
        HandlerMethod handlerMethod = handlerMethodFor("protectedMethod");
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        when(request.getHeader("Authorization")).thenReturn("Bearer good-token");
        JwtClaims claims = new JwtClaims("1", "a@b.com", "auth-service", "web", "sess", null, null);
        when(jwtVerificationService.verify("good-token")).thenReturn(JwtVerificationResult.success(claims));

        boolean result = interceptor.preHandle(request, response, handlerMethod);

        assertThat(result).isTrue();
        verify(request).setAttribute(JwtAuthenticationInterceptor.CLAIMS_ATTRIBUTE, claims);
    }

    @Test
    void rejectsAnnotatedMethodWithInvalidTokenWithoutLeakingVerificationFailureReason() throws Exception {
        HandlerMethod handlerMethod = handlerMethodFor("protectedMethod");
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        when(request.getHeader("Authorization")).thenReturn("Bearer bad-token");
        String attackerInfluencedReason = "invalid issuer: attacker-controlled-issuer-value";
        when(jwtVerificationService.verify("bad-token"))
            .thenReturn(JwtVerificationResult.failure(attackerInfluencedReason));

        boolean result = interceptor.preHandle(request, response, handlerMethod);

        assertThat(result).isFalse();
        ArgumentCaptor<String> messageCaptor = ArgumentCaptor.forClass(String.class);
        verify(response).sendError(eq(HttpServletResponse.SC_UNAUTHORIZED), messageCaptor.capture());
        assertThat(messageCaptor.getValue())
            .isNotEqualTo(attackerInfluencedReason)
            .doesNotContain("attacker-controlled-issuer-value");
        verify(request, never()).setAttribute(anyString(), any());
    }

    @Test
    void rejectsWhenClassLevelAnnotationIsPresentButMethodIsUnannotated() throws Exception {
        Method method = ClassAnnotatedController.class.getMethod("openMethod");
        HandlerMethod handlerMethod = new HandlerMethod(new ClassAnnotatedController(), method);
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        when(request.getHeader("Authorization")).thenReturn(null);

        boolean result = interceptor.preHandle(request, response, handlerMethod);

        assertThat(result).isFalse();
        verify(response).sendError(eq(HttpServletResponse.SC_UNAUTHORIZED), anyString());
        verify(request, never()).setAttribute(anyString(), any());
        verifyNoInteractions(jwtVerificationService);
    }

    @Test
    void rejectsWhenAnnotationIsInheritedFromSuperclass() throws Exception {
        // pins Fix 1: the old code resolved the class-level annotation with a raw
        // getAnnotation() call, which ignores superclasses because @JwtTokenVerification is
        // not @Inherited. InheritingProtectedController does not carry the annotation itself -
        // only its superclass, BaseProtectedController, does - so the old behaviour would
        // treat this handler as unprotected and let the request through without a token.
        Method method = InheritingProtectedController.class.getMethod("baseMethod");
        HandlerMethod handlerMethod = new HandlerMethod(new InheritingProtectedController(), method);
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        when(request.getHeader("Authorization")).thenReturn(null);

        boolean result = interceptor.preHandle(request, response, handlerMethod);

        assertThat(result).isFalse();
        verify(response).sendError(eq(HttpServletResponse.SC_UNAUTHORIZED), anyString());
        verify(request, never()).setAttribute(anyString(), any());
        verifyNoInteractions(jwtVerificationService);
    }

    @Test
    void rejectsValidResultWithNullClaimsAndNeverExposesThem() throws Exception {
        // pins Fix 2: a JwtVerificationService implementation that returns valid() == true
        // together with claims() == null (e.g. a buggy consumer-supplied bean, since the
        // interface is replaceable via @ConditionalOnMissingBean) must not let the request
        // through - downstream code dereferences claims fields unconditionally.
        HandlerMethod handlerMethod = handlerMethodFor("protectedMethod");
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        when(request.getHeader("Authorization")).thenReturn("Bearer good-token");
        when(jwtVerificationService.verify("good-token")).thenReturn(JwtVerificationResult.success(null));

        boolean result = interceptor.preHandle(request, response, handlerMethod);

        assertThat(result).isFalse();
        verify(response).sendError(eq(HttpServletResponse.SC_UNAUTHORIZED), anyString());
        verify(request, never()).setAttribute(anyString(), any());
    }

    @Test
    void acceptsLowercaseBearerScheme() throws Exception {
        // pins Fix 6: RFC 6750 auth-scheme matching is case-insensitive.
        HandlerMethod handlerMethod = handlerMethodFor("protectedMethod");
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        when(request.getHeader("Authorization")).thenReturn("bearer good-token");
        JwtClaims claims = new JwtClaims("1", "a@b.com", "auth-service", "web", "sess", null, null);
        when(jwtVerificationService.verify("good-token")).thenReturn(JwtVerificationResult.success(claims));

        boolean result = interceptor.preHandle(request, response, handlerMethod);

        assertThat(result).isTrue();
        verify(request).setAttribute(JwtAuthenticationInterceptor.CLAIMS_ATTRIBUTE, claims);
    }

    @Test
    void nonHandlerMethodHandlerIsAllowedWithoutTouchingVerificationService() throws Exception {
        // documents the static-resource path: preHandle is invoked for every request the
        // servlet dispatcher handles, not just @Controller methods, and non-HandlerMethod
        // handlers (e.g. ResourceHttpRequestHandler for static resources) must pass through.
        Object handler = new Object();
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);

        boolean result = interceptor.preHandle(request, response, handler);

        assertThat(result).isTrue();
        verifyNoInteractions(jwtVerificationService);
        verifyNoInteractions(request);
    }

    private HandlerMethod handlerMethodFor(String methodName) throws NoSuchMethodException {
        ProtectedController bean = new ProtectedController();
        Method method = ProtectedController.class.getMethod(methodName);
        return new HandlerMethod(bean, method);
    }
}
