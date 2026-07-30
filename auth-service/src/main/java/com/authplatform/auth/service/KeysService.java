package com.authplatform.auth.service;

import com.authplatform.auth.entity.CertificateEntity;
import com.nimbusds.jose.jwk.RSAKey;

import java.security.interfaces.RSAPrivateKey;
import java.util.List;

public interface KeysService {
    CertificateEntity getActiveKey();
    RSAKey toPublicJwk(CertificateEntity certificate);
    RSAPrivateKey toPrivateKey(CertificateEntity certificate);

    /**
     * The public half of every stored signing key (active and rotated-out alike), for
     * publishing at the JWKS endpoint. A verifier resolves the correct key by {@code kid}, so
     * every key that may have signed a still-unexpired token must be included - not just the
     * currently active one. On a genuinely empty database this still returns the first
     * generated key rather than an empty list.
     */
    List<RSAKey> getAllPublicJwks();
}
