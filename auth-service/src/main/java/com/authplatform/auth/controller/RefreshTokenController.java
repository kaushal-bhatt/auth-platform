package com.authplatform.auth.controller;

import com.authplatform.auth.dto.RefreshRequest;
import com.authplatform.auth.dto.TokenResponse;
import com.authplatform.auth.service.TokenService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Exposes {@link TokenService#refresh(String)} over HTTP. The service is the sole source of
 * truth for what counts as a valid refresh token; this controller adds no additional checks or
 * distinguishing error detail on top of it, and never logs the incoming token.
 */
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class RefreshTokenController {

    private final TokenService tokenService;

    @PostMapping("/refresh")
    public TokenResponse refresh(@Valid @RequestBody RefreshRequest request) {
        return tokenService.refresh(request.refreshToken());
    }
}
