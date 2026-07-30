package com.authplatform.auth.repository;

import com.authplatform.auth.entity.CertificateEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface CertificateRepository extends JpaRepository<CertificateEntity, UUID> {
    Optional<CertificateEntity> findFirstByActiveTrueOrderByCreatedAtDesc();

    /**
     * All stored certificates (active and rotated-out) in a stable, deterministic order, so the
     * JWKS endpoint's {@code keys} array is not arbitrary from request to request. Rotated-out
     * keys must still be published here - a token they signed remains valid until it expires,
     * and a verifier resolves the signing key by {@code kid}, not by "is this the active one".
     */
    List<CertificateEntity> findAllByOrderByCreatedAtAsc();
}
