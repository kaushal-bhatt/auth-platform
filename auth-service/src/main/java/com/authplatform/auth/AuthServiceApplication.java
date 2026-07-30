package com.authplatform.auth;

import com.authplatform.auth.config.JwtIssuerProperties;
import com.authplatform.auth.config.WebAuthnProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties({JwtIssuerProperties.class, WebAuthnProperties.class})
public class AuthServiceApplication {
    public static void main(String[] args) {
        SpringApplication.run(AuthServiceApplication.class, args);
    }
}
