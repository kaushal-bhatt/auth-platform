package com.authplatform.auth.repository;

import com.authplatform.auth.entity.PasskeyCredentialEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface PasskeyCredentialRepository extends JpaRepository<PasskeyCredentialEntity, UUID> {
    Optional<PasskeyCredentialEntity> findByCredentialId(String credentialId);
    List<PasskeyCredentialEntity> findByUserId(Long userId);
}
