package com.authplatform.auth.service;

import com.authplatform.auth.dto.TokenResponse;

public interface TokenService {
    TokenResponse issueTokens(Long userId, String email);
    TokenResponse refresh(String refreshToken);
}
