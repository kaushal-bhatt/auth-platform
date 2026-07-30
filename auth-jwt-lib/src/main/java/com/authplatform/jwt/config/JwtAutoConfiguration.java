package com.authplatform.jwt.config;

import com.authplatform.jwt.interceptor.JwtAuthenticationInterceptor;
import com.authplatform.jwt.service.JwksClient;
import com.authplatform.jwt.service.JwtVerificationService;
import com.authplatform.jwt.service.impl.JwksClientImpl;
import com.authplatform.jwt.service.impl.JwtVerificationServiceImpl;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.util.StringUtils;

/**
 * auto-configures jwt verification and enforcement for a spring boot servlet web
 * application. registered unconditionally (subject to the servlet web application check
 * below) via {@code META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports}
 * so that jwt enforcement is active as soon as this library is on the classpath - it is not
 * gated behind {@code @EnableJwtAuthentication} or any property, since doing so would make it
 * possible to ship a service with silently disabled jwt enforcement.
 */
@AutoConfiguration
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@EnableConfigurationProperties(JwtLibProperties.class)
@Import(JwtWebConfig.class)
public class JwtAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public JwksClient jwksClient(JwtLibProperties properties) {
        requireProperty(properties.getJwksUri(), "auth-platform.jwt.jwks-uri");
        return new JwksClientImpl(properties);
    }

    @Bean
    @ConditionalOnMissingBean
    public JwtVerificationService jwtVerificationService(JwksClient jwksClient, JwtLibProperties properties) {
        requireProperty(properties.getExpectedIssuer(), "auth-platform.jwt.expected-issuer");
        return new JwtVerificationServiceImpl(jwksClient, properties);
    }

    @Bean
    @ConditionalOnMissingBean
    public JwtAuthenticationInterceptor jwtAuthenticationInterceptor(JwtVerificationService jwtVerificationService) {
        return new JwtAuthenticationInterceptor(jwtVerificationService);
    }

    /**
     * fails startup fast with an actionable message when a required {@code auth-platform.jwt.*}
     * property is missing, instead of letting the application boot and then 401 every protected
     * request with the real cause only visible at debug level.
     */
    private static void requireProperty(String value, String propertyKey) {
        if (!StringUtils.hasText(value)) {
            throw new IllegalStateException(
                "missing required configuration property '" + propertyKey + "': auth-jwt-lib cannot "
                    + "verify jwt tokens without it. set it in application.yml/application.properties.");
        }
    }
}
