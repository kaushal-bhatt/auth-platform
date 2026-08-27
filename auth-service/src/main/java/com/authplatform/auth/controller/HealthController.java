package com.authplatform.auth.controller;

import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * A trivial, unauthenticated liveness probe for container orchestration (an ECS/target-group
 * health check, or an uptime pinger). It deliberately does no dependency checks - it answers
 * {@code 200} as soon as the web context is up, which is exactly the signal a scheduler needs to
 * know the process is accepting traffic. It carries no {@code @JwtTokenVerification}, so it is
 * public by design.
 */
@RestController
public class HealthController {

    @GetMapping("/health")
    public Map<String, String> health() {
        return Map.of("status", "UP");
    }
}
