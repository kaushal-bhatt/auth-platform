package com.authplatform.jwt.annotation;

import com.authplatform.jwt.config.JwtAutoConfiguration;
import com.authplatform.jwt.config.JwtLibProperties;
import com.authplatform.jwt.config.JwtWebConfig;
import com.authplatform.jwt.interceptor.JwtAuthenticationInterceptor;
import com.authplatform.jwt.service.JwksClient;
import com.authplatform.jwt.service.JwtVerificationService;
import com.authplatform.jwt.service.impl.JwksClientImpl;
import com.authplatform.jwt.service.impl.JwtVerificationServiceImpl;
import org.junit.jupiter.api.Test;
import org.springframework.context.annotation.Configuration;
import org.springframework.mock.env.MockPropertySource;
import org.springframework.mock.web.MockServletContext;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * {@link EnableJwtAuthentication} is used by nothing in this repository, and its documented reason
 * to exist is the one case Spring Boot's {@code AutoConfiguration.imports} mechanism cannot serve:
 * a plain, non-Boot Spring application, where {@code @Import} on a {@code @Configuration} class is
 * the only way to pull {@link JwtAutoConfiguration} in. That claim was asserted nowhere, so this
 * class pins it against a real, hand-built {@link AnnotationConfigWebApplicationContext} - no
 * {@code SpringApplication}, no auto-configuration import mechanism, no
 * {@code ApplicationContextRunner}.
 */
class EnableJwtAuthenticationTest {

    private static final String JWKS_URI = "http://localhost:1/.well-known/jwks.json";

    @Test
    void importsTheJwtBeansIntoAPlainNonBootSpringServletContext() {
        try (AnnotationConfigWebApplicationContext context = plainSpringContext()) {
            context.getEnvironment().getPropertySources().addFirst(new MockPropertySource()
                .withProperty("auth-platform.jwt.jwks-uri", JWKS_URI)
                .withProperty("auth-platform.jwt.expected-issuer", "auth-service"));
            context.register(AnnotatedConfig.class);

            context.refresh();

            assertThat(context.getBean(JwksClient.class)).isInstanceOf(JwksClientImpl.class);
            assertThat(context.getBean(JwtVerificationService.class)).isInstanceOf(JwtVerificationServiceImpl.class);
            assertThat(context.getBean(JwtAuthenticationInterceptor.class)).isNotNull();
            assertThat(context.getBean(JwtWebConfig.class)).isNotNull();
            // @EnableConfigurationProperties must still bind in a plain context, otherwise the
            // beans above would be constructed from empty properties.
            assertThat(context.getBean(JwtLibProperties.class).getJwksUri()).isEqualTo(JWKS_URI);
            assertThat(context.getBean(JwtLibProperties.class).getExpectedIssuer()).isEqualTo("auth-service");
        }
    }

    /**
     * Without the annotation there is no auto-configuration mechanism in a plain Spring context, so
     * nothing is registered at all. This is what makes the annotation load-bearing here rather than
     * merely decorative, and it is why the previous test proves something.
     */
    @Test
    void aPlainNonBootContextWithoutTheAnnotationGetsNothing() {
        try (AnnotationConfigWebApplicationContext context = plainSpringContext()) {
            context.register(UnannotatedConfig.class);

            context.refresh();

            assertThat(context.getBeanNamesForType(JwtAuthenticationInterceptor.class)).isEmpty();
            assertThat(context.getBeanNamesForType(JwtVerificationService.class)).isEmpty();
        }
    }

    /**
     * The fail-fast contract holds in a plain context too - a missing required property is a
     * startup failure naming the property, not a service that boots and 401s everything.
     */
    @Test
    void stillFailsFastOnAMissingRequiredPropertyInAPlainNonBootContext() {
        try (AnnotationConfigWebApplicationContext context = plainSpringContext()) {
            context.register(AnnotatedConfig.class);

            assertThatThrownBy(context::refresh)
                .rootCause()
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("auth-platform.jwt.jwks-uri");
        }
    }

    private static AnnotationConfigWebApplicationContext plainSpringContext() {
        AnnotationConfigWebApplicationContext context = new AnnotationConfigWebApplicationContext();
        // a servlet context is what makes @ConditionalOnWebApplication(SERVLET) match; the
        // library deliberately contributes nothing without one.
        context.setServletContext(new MockServletContext());
        return context;
    }

    @EnableJwtAuthentication
    @Configuration(proxyBeanMethods = false)
    static class AnnotatedConfig {
    }

    @Configuration(proxyBeanMethods = false)
    static class UnannotatedConfig {
    }
}
