package com.authplatform.auth.controller;

import com.authplatform.auth.dto.PasskeyRegisterCompleteRequest;
import com.authplatform.auth.dto.PasskeyRegisterInitResponse;
import com.authplatform.auth.service.PasskeyRegistrationService;
import com.authplatform.auth.util.VerifiedCaller;
import com.authplatform.jwt.annotation.JwtTokenVerification;
import com.authplatform.jwt.model.JwtClaims;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Both endpoints require a verified bearer token - the class-level {@link JwtTokenVerification}
 * is enforced by auth-jwt-lib's {@code JwtAuthenticationInterceptor} - and the acting user is
 * always taken from the verified {@link JwtClaims} on the request, never from any client-supplied
 * id in the body.
 */
@RestController
@RequestMapping("/passkey/register")
@RequiredArgsConstructor
@JwtTokenVerification
public class PasskeyRegistrationController {

    private final PasskeyRegistrationService passkeyRegistrationService;

    @PostMapping("/init")
    public PasskeyRegisterInitResponse init(HttpServletRequest request) {
        return passkeyRegistrationService.initRegistration(VerifiedCaller.requireUserId(request));
    }

    @PostMapping("/complete")
    public void complete(HttpServletRequest request, @Valid @RequestBody PasskeyRegisterCompleteRequest completeRequest) {
        passkeyRegistrationService.completeRegistration(VerifiedCaller.requireUserId(request), completeRequest);
    }
}
