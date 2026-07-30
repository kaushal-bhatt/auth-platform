package com.authplatform.jwt.config;

import com.authplatform.jwt.annotation.JwtTokenVerification;
import com.authplatform.jwt.interceptor.JwtAuthenticationInterceptor;
import com.authplatform.jwt.model.JwtClaims;
import com.authplatform.jwt.model.JwtVerificationResult;
import com.authplatform.jwt.service.JwksClient;
import com.authplatform.jwt.service.JwtVerificationService;
import com.authplatform.jwt.service.impl.JwksClientImpl;
import com.authplatform.jwt.service.impl.JwtVerificationServiceImpl;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.context.annotation.ImportCandidates;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

/**
 * The library's central promise - "put it on the classpath, set two properties, and every
 * {@code @JwtTokenVerification} handler is enforced" - lives entirely in
 * {@link JwtAutoConfiguration} plus the {@code AutoConfiguration.imports} registration file, and
 * was previously asserted nowhere. Deleting that one-line imports file left every other test in
 * this module green while silently turning the library into a no-op for every consumer, which is
 * the specific regression {@link #autoConfigurationImportsFileRegistersThisAutoConfiguration()}
 * exists to catch.
 */
class JwtAutoConfigurationTest {

    private static final String IMPORTS_FILE =
        "META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports";

    /**
     * Deliberately points at a port nothing is listening on: no test in this class needs a real
     * jwks document, and a bean that silently reached the network to be constructed would be the
     * wrong design to pin.
     */
    private static final String JWKS_URI_PROPERTY =
        "auth-platform.jwt.jwks-uri=http://localhost:1/.well-known/jwks.json";
    private static final String EXPECTED_ISSUER_PROPERTY = "auth-platform.jwt.expected-issuer=auth-service";

    private final WebApplicationContextRunner servletRunner = new WebApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(JwtAutoConfiguration.class));

    @Test
    void registersEveryVerificationBeanWhenBothRequiredPropertiesArePresent() {
        servletRunner.withPropertyValues(JWKS_URI_PROPERTY, EXPECTED_ISSUER_PROPERTY).run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).hasSingleBean(JwtLibProperties.class);
            assertThat(context).hasSingleBean(JwksClient.class);
            assertThat(context).hasSingleBean(JwtVerificationService.class);
            assertThat(context).hasSingleBean(JwtAuthenticationInterceptor.class);
            assertThat(context.getBean(JwksClient.class)).isInstanceOf(JwksClientImpl.class);
            assertThat(context.getBean(JwtVerificationService.class)).isInstanceOf(JwtVerificationServiceImpl.class);
        });
    }

    @Test
    void bindsTheConfiguredPropertiesOntoJwtLibProperties() {
        servletRunner
            .withPropertyValues(
                JWKS_URI_PROPERTY,
                EXPECTED_ISSUER_PROPERTY,
                "auth-platform.jwt.expected-audience=auth-platform-client",
                "auth-platform.jwt.min-refresh-interval-seconds=120")
            .run(context -> {
                JwtLibProperties properties = context.getBean(JwtLibProperties.class);
                assertThat(properties.getJwksUri()).isEqualTo("http://localhost:1/.well-known/jwks.json");
                assertThat(properties.getExpectedIssuer()).isEqualTo("auth-service");
                assertThat(properties.getExpectedAudience()).isEqualTo("auth-platform-client");
                assertThat(properties.getMinRefreshIntervalSeconds()).isEqualTo(120L);
            });
    }

    /**
     * Registering {@link JwtWebConfig} is not enough on its own - it has to actually hand the
     * interceptor to Spring MVC, otherwise every {@code @JwtTokenVerification} handler is public.
     */
    @Test
    void importsJwtWebConfigWhichRegistersTheInterceptorWithSpringMvc() {
        servletRunner.withPropertyValues(JWKS_URI_PROPERTY, EXPECTED_ISSUER_PROPERTY).run(context -> {
            assertThat(context).hasSingleBean(JwtWebConfig.class);

            ExposedInterceptorRegistry registry = new ExposedInterceptorRegistry();
            context.getBean(JwtWebConfig.class).addInterceptors(registry);

            assertThat(registry.registeredInterceptors())
                .containsExactly(context.getBean(JwtAuthenticationInterceptor.class));
        });
    }

    @Test
    void failsStartupNamingJwksUriWhenThePropertyIsAbsent() {
        servletRunner.withPropertyValues(EXPECTED_ISSUER_PROPERTY).run(context -> {
            assertThat(context).hasFailed();
            assertThat(context).getFailure()
                .rootCause()
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("auth-platform.jwt.jwks-uri");
        });
    }

    @Test
    void failsStartupNamingJwksUriWhenThePropertyIsBlank() {
        servletRunner.withPropertyValues("auth-platform.jwt.jwks-uri=   ", EXPECTED_ISSUER_PROPERTY).run(context -> {
            assertThat(context).hasFailed();
            assertThat(context).getFailure()
                .rootCause()
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("auth-platform.jwt.jwks-uri");
        });
    }

    @Test
    void failsStartupNamingExpectedIssuerWhenThePropertyIsAbsent() {
        servletRunner.withPropertyValues(JWKS_URI_PROPERTY).run(context -> {
            assertThat(context).hasFailed();
            assertThat(context).getFailure()
                .rootCause()
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("auth-platform.jwt.expected-issuer");
        });
    }

    @Test
    void failsStartupNamingExpectedIssuerWhenThePropertyIsBlank() {
        servletRunner.withPropertyValues(JWKS_URI_PROPERTY, "auth-platform.jwt.expected-issuer=   ").run(context -> {
            assertThat(context).hasFailed();
            assertThat(context).getFailure()
                .rootCause()
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("auth-platform.jwt.expected-issuer");
        });
    }

    /**
     * {@code @ConditionalOnMissingBean} has to genuinely back off: a host that supplies its own
     * {@link JwtVerificationService} (e.g. to verify tokens from a different issuer, or to add
     * revocation checks) must have the interceptor call <em>its</em> implementation, not merely
     * end up with two beans or with the library's one still wired in.
     */
    @Test
    void yieldsToAHostSuppliedJwtVerificationService() {
        servletRunner
            .withPropertyValues(JWKS_URI_PROPERTY, EXPECTED_ISSUER_PROPERTY)
            .withUserConfiguration(HostSuppliedVerificationServiceConfig.class)
            .run(context -> {
                assertThat(context).hasNotFailed();
                assertThat(context).hasSingleBean(JwtVerificationService.class);
                assertThat(context.getBean(JwtVerificationService.class))
                    .isInstanceOf(RecordingJwtVerificationService.class)
                    .isNotInstanceOf(JwtVerificationServiceImpl.class);

                // prove it by behaviour, not just by type: drive a protected handler through the
                // auto-configured interceptor and check whose verifier saw the token.
                RecordingJwtVerificationService hostService =
                    context.getBean(RecordingJwtVerificationService.class);
                MockHttpServletRequest request = new MockHttpServletRequest();
                request.addHeader("Authorization", "Bearer host-verified-token");
                MockHttpServletResponse response = new MockHttpServletResponse();

                boolean proceeded = context.getBean(JwtAuthenticationInterceptor.class)
                    .preHandle(request, response, protectedHandlerMethod());

                assertThat(proceeded).isTrue();
                assertThat(hostService.tokensSeen).containsExactly("host-verified-token");
                assertThat(request.getAttribute(JwtAuthenticationInterceptor.CLAIMS_ATTRIBUTE))
                    .isSameAs(RecordingJwtVerificationService.CLAIMS);
            });
    }

    /**
     * {@code @ConditionalOnWebApplication(SERVLET)} must keep the whole auto-configuration inert
     * in a batch job / CLI / reactive application, rather than failing its startup over jwt
     * properties it has no use for.
     */
    @Test
    void staysInertInANonServletApplication() {
        new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(JwtAutoConfiguration.class))
            .withPropertyValues(JWKS_URI_PROPERTY, EXPECTED_ISSUER_PROPERTY)
            .run(context -> {
                assertThat(context).hasNotFailed();
                assertThat(context).doesNotHaveBean(JwksClient.class);
                assertThat(context).doesNotHaveBean(JwtVerificationService.class);
                assertThat(context).doesNotHaveBean(JwtAuthenticationInterceptor.class);
                assertThat(context).doesNotHaveBean(JwtWebConfig.class);
            });
    }

    /**
     * A non-servlet application must not be forced to configure jwt properties it cannot use
     * either - the conditional has to be evaluated before {@code requireProperty} runs.
     */
    @Test
    void staysInertInANonServletApplicationEvenWithNoJwtPropertiesAtAll() {
        new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(JwtAutoConfiguration.class))
            .run(context -> {
                assertThat(context).hasNotFailed();
                assertThat(context).doesNotHaveBean(JwtAuthenticationInterceptor.class);
            });
    }

    /**
     * The registration file is the single line of the library that makes it self-configuring in a
     * consumer, and a typo or a deletion in it cannot be caught by any behavioural test in this
     * module (they all name {@link JwtAutoConfiguration} explicitly). So assert the file itself,
     * both as raw classpath text and through Spring Boot's own candidate loader.
     */
    @Test
    void autoConfigurationImportsFileRegistersThisAutoConfiguration() throws IOException {
        ClassPathResource resource = new ClassPathResource(IMPORTS_FILE);
        assertThat(resource.exists())
            .as("auth-jwt-lib must ship %s; without it spring boot never imports "
                + "JwtAutoConfiguration and the library silently enforces nothing", IMPORTS_FILE)
            .isTrue();

        List<String> declaredClassNames = declaredClassNames(resource);

        assertThat(declaredClassNames).contains(JwtAutoConfiguration.class.getName());
        for (String className : declaredClassNames) {
            assertThatCode(() -> Class.forName(className))
                .as("%s names '%s', which does not resolve to a real class", IMPORTS_FILE, className)
                .doesNotThrowAnyException();
        }

        List<String> springBootCandidates = new ArrayList<>();
        ImportCandidates.load(AutoConfiguration.class, getClass().getClassLoader()).forEach(springBootCandidates::add);
        assertThat(springBootCandidates)
            .as("spring boot's own ImportCandidates loader must discover JwtAutoConfiguration")
            .contains(JwtAutoConfiguration.class.getName());
    }

    private static List<String> declaredClassNames(ClassPathResource resource) throws IOException {
        String content = new String(resource.getContentAsByteArray(), StandardCharsets.UTF_8);
        return Stream.of(content.split("\\R"))
            .map(String::trim)
            .filter(line -> !line.isEmpty() && !line.startsWith("#"))
            .toList();
    }

    private static HandlerMethod protectedHandlerMethod() throws NoSuchMethodException {
        return new HandlerMethod(new ProtectedHandler(), ProtectedHandler.class.getMethod("protectedMethod"));
    }

    static class ProtectedHandler {
        @JwtTokenVerification
        public void protectedMethod() {
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class HostSuppliedVerificationServiceConfig {

        @Bean
        RecordingJwtVerificationService hostJwtVerificationService() {
            return new RecordingJwtVerificationService();
        }
    }

    /**
     * Stands in for a host application's own verifier. Records what it was asked to verify so a
     * test can prove the auto-configured interceptor consulted this instance and not the
     * library's {@link JwtVerificationServiceImpl}.
     */
    static class RecordingJwtVerificationService implements JwtVerificationService {

        static final JwtClaims CLAIMS = new JwtClaims(
            "42", "host@example.com", "host-issuer", null, "host-session",
            Instant.EPOCH, Instant.EPOCH.plusSeconds(900));

        private final List<String> tokensSeen = new ArrayList<>();

        @Override
        public JwtVerificationResult verify(String token) {
            tokensSeen.add(token);
            return JwtVerificationResult.success(CLAIMS);
        }

        @Override
        public JwtClaims extractClaimsWithoutVerification(String token) {
            return CLAIMS;
        }
    }

    /**
     * {@code InterceptorRegistry#getInterceptors()} is protected, so a subclass is the only way to
     * read back what {@link JwtWebConfig} registered.
     */
    private static final class ExposedInterceptorRegistry extends InterceptorRegistry {

        List<Object> registeredInterceptors() {
            return getInterceptors();
        }
    }
}
