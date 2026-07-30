package com.authplatform.auth.service.impl;

import com.authplatform.auth.dto.LoginRequest;
import com.authplatform.auth.dto.TokenResponse;
import com.authplatform.auth.entity.UserEntity;
import com.authplatform.auth.exception.CustomException;
import com.authplatform.auth.repository.UserRepository;
import com.authplatform.auth.service.LoginService;
import com.authplatform.auth.service.TokenService;
import com.authplatform.auth.util.EmailNormalizer;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class LoginServiceImpl implements LoginService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final TokenService tokenService;

    @Override
    public TokenResponse login(LoginRequest request) {
        // Normalise before lookup: Task 7 stores emails normalised (trimmed + lower-cased
        // via EmailNormalizer), so comparing the raw input here would make case/whitespace
        // variants of a registered email unable to log in. See EmailNormalizer's javadoc -
        // every user-by-email lookup in this project must go through it.
        String normalizedEmail = EmailNormalizer.normalize(request.email());

        UserEntity user = userRepository.findByEmail(normalizedEmail)
            .orElseThrow(() -> new CustomException(401, "invalid email or password"));

        if (!passwordEncoder.matches(request.password(), user.getPasswordHash())) {
            throw new CustomException(401, "invalid email or password");
        }

        return tokenService.issueTokens(user.getId(), user.getEmail());
    }
}
