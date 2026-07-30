package com.authplatform.jwt.service;

import com.nimbusds.jose.jwk.RSAKey;

import java.util.Optional;

public interface JwksClient {
    Optional<RSAKey> getKey(String keyId);
    void refresh();
}
