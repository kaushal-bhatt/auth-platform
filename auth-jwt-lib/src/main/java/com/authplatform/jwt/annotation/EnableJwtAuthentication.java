package com.authplatform.jwt.annotation;

import com.authplatform.jwt.config.JwtAutoConfiguration;
import org.springframework.context.annotation.Import;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * opts a configuration class into jwt authentication enforcement.
 *
 * <p><strong>in a spring boot application this annotation is optional.</strong> auth-jwt-lib
 * ships a {@code META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports}
 * entry for {@link JwtAutoConfiguration}, so jwt enforcement is auto-configured and active as
 * soon as the library is on the classpath of a servlet-based spring boot application - with or
 * without this annotation. It is deliberately not possible to disable or gate that
 * auto-configuration behind this annotation or a property, since doing so would allow a service
 * to silently ship with no jwt enforcement.
 *
 * <p>this annotation exists for two narrower cases: (1) a plain, non-boot spring application
 * that has no auto-configuration mechanism, where placing {@code @EnableJwtAuthentication} on a
 * {@code @Configuration} class is the only way to import {@link JwtAutoConfiguration}; and (2)
 * as an explicit, self-documenting marker of the dependency on jwt enforcement for readers of a
 * boot application's configuration, even though it has no additional effect there.
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Import(JwtAutoConfiguration.class)
public @interface EnableJwtAuthentication {
}
