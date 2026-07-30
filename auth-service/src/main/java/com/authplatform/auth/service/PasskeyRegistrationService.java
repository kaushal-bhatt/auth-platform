package com.authplatform.auth.service;

import com.authplatform.auth.dto.PasskeyRegisterCompleteRequest;
import com.authplatform.auth.dto.PasskeyRegisterInitResponse;

public interface PasskeyRegistrationService {
    PasskeyRegisterInitResponse initRegistration(Long userId);
    void completeRegistration(Long userId, PasskeyRegisterCompleteRequest request);
}
