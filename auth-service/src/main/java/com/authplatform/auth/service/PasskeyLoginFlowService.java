package com.authplatform.auth.service;

import com.authplatform.auth.dto.PasskeyLoginCompleteRequest;
import com.authplatform.auth.dto.PasskeyLoginInitResponse;
import com.authplatform.auth.dto.TokenResponse;

public interface PasskeyLoginFlowService {
    PasskeyLoginInitResponse initLogin(String email);
    TokenResponse completeLogin(PasskeyLoginCompleteRequest request);
}
