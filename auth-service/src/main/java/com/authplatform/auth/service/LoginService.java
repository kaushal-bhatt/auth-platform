package com.authplatform.auth.service;

import com.authplatform.auth.dto.LoginRequest;
import com.authplatform.auth.dto.TokenResponse;

public interface LoginService {
    TokenResponse login(LoginRequest request);
}
