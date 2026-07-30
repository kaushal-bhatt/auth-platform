package com.authplatform.auth.controller;

import com.authplatform.auth.dto.PasskeyCredentialSummary;
import com.authplatform.auth.entity.PasskeyCredentialEntity;
import com.authplatform.auth.exception.CustomException;
import com.authplatform.auth.repository.PasskeyCredentialRepository;
import com.authplatform.auth.util.VerifiedCaller;
import com.authplatform.jwt.annotation.JwtTokenVerification;
import com.authplatform.jwt.model.JwtClaims;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Lists and deletes the authenticated caller's own passkeys. Protected end-to-end by
 * auth-jwt-lib's {@link JwtTokenVerification}: an unauthenticated request never reaches either
 * handler method (see {@code JwtAuthenticationInterceptor}), and the acting user's id is read
 * only from the verified {@link JwtClaims} on the request attribute - never from the path or
 * body - so one user can never list or delete another user's credentials. {@link #delete}
 * scopes the lookup to {@code userId} before deleting, so a request for a credential id that
 * exists but belongs to someone else 404s exactly like an unknown id - it must never leak via a
 * 403 (which would confirm the credential exists) or a 200 (which would delete someone else's
 * passkey).
 */
@RestController
@RequestMapping("/passkey")
@RequiredArgsConstructor
@JwtTokenVerification
public class PasskeyController {

    private final PasskeyCredentialRepository passkeyCredentialRepository;

    @GetMapping
    public List<PasskeyCredentialSummary> list(HttpServletRequest request) {
        Long userId = VerifiedCaller.requireUserId(request);
        return passkeyCredentialRepository.findByUserId(userId).stream()
            .map(c -> new PasskeyCredentialSummary(c.getCredentialId(), c.getCreatedAt()))
            .toList();
    }

    @DeleteMapping("/{credentialId}")
    public void delete(HttpServletRequest request, @PathVariable String credentialId) {
        Long userId = VerifiedCaller.requireUserId(request);
        PasskeyCredentialEntity credential = passkeyCredentialRepository.findByCredentialId(credentialId)
            .filter(c -> c.getUserId().equals(userId))
            .orElseThrow(() -> new CustomException(404, "passkey not found"));
        passkeyCredentialRepository.delete(credential);
    }
}
