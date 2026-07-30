package com.authplatform.auth.service;

import com.authplatform.auth.dto.RegisterRequest;

public interface RegistrationService {
    void register(RegisterRequest request);
}
