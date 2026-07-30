package com.authplatform.auth.controller;

import com.authplatform.auth.dto.PasskeyLoginCompleteRequest;
import com.authplatform.auth.dto.PasskeyLoginInitResponse;
import com.authplatform.auth.dto.TokenResponse;
import com.authplatform.auth.service.PasskeyLoginFlowService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * The passkey equivalent of {@link AuthController#login}: a public, unauthenticated ceremony, so
 * neither endpoint carries {@code @JwtTokenVerification} - there is no bearer token to verify yet
 * because logging in is how a caller obtains one. See {@code PasskeyLoginFlowServiceImpl}'s
 * javadoc for the security properties this relies on instead (challenge ownership, sign-count
 * anti-replay, server-side-only origin/rpId, and the uniform-failure response that prevents
 * {@link #init} from being used to enumerate registered emails).
 */
@RestController
@RequestMapping("/passkey/login")
@RequiredArgsConstructor
public class PasskeyLoginController {

    private final PasskeyLoginFlowService passkeyLoginFlowService;

    public record InitRequest(@NotBlank String email) {
    }

    @PostMapping("/init")
    public PasskeyLoginInitResponse init(@Valid @RequestBody InitRequest request) {
        return passkeyLoginFlowService.initLogin(request.email());
    }

    @PostMapping("/complete")
    public TokenResponse complete(@Valid @RequestBody PasskeyLoginCompleteRequest request) {
        return passkeyLoginFlowService.completeLogin(request);
    }
}
