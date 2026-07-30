package com.authplatform.auth.service.impl;

import com.authplatform.auth.dto.RegisterRequest;
import com.authplatform.auth.entity.UserEntity;
import com.authplatform.auth.exception.CustomException;
import com.authplatform.auth.repository.UserRepository;
import com.authplatform.auth.service.RegistrationService;
import com.authplatform.auth.util.EmailNormalizer;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;

@Service
@RequiredArgsConstructor
public class RegistrationServiceImpl implements RegistrationService {

    // BCrypt (see PasswordEncoderConfig) silently truncates its input at 72 bytes, so two
    // different passwords sharing the first 72 bytes would hash identically and both verify.
    // Do NOT raise this limit - it is a hard ceiling of the BCrypt algorithm, not a tunable.
    private static final int BCRYPT_MAX_PASSWORD_BYTES = 72;

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    @Transactional
    public void register(RegisterRequest request) {
        // @Size on RegisterRequest counts UTF-16 chars, not bytes, so a password within the
        // char limit can still exceed the BCrypt byte limit once multi-byte UTF-8 characters
        // are involved. Enforce the real limit explicitly here.
        if (request.password().getBytes(StandardCharsets.UTF_8).length > BCRYPT_MAX_PASSWORD_BYTES) {
            throw new CustomException(400, "password is too long once encoded as utf-8");
        }

        // Normalise on both sides of the check so what is verified against the database is
        // exactly what gets stored on the entity. See EmailNormalizer's javadoc.
        String normalizedEmail = EmailNormalizer.normalize(request.email());
        if (userRepository.existsByEmail(normalizedEmail)) {
            throw new CustomException(409, "email is already registered");
        }

        // createdAt/updatedAt are stamped by UserEntity's @PrePersist lifecycle callback.
        UserEntity user = UserEntity.builder()
            .email(normalizedEmail)
            .passwordHash(passwordEncoder.encode(request.password()))
            .build();
        userRepository.save(user);
    }
}
