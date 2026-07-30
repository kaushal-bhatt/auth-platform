package com.authplatform.auth.service.impl;

import com.authplatform.auth.entity.CertificateEntity;
import com.authplatform.auth.repository.CertificateRepository;
import com.authplatform.auth.security.KeyProtector;
import com.authplatform.auth.service.KeysService;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class KeysServiceImpl implements KeysService, InitializingBean {

    private static final String KEY_PROTECTION_SECRET_PROPERTY = "auth-platform.issuer.key-protection-secret";

    private final CertificateRepository certificateRepository;
    private final KeyProtector keyProtector;

    @Override
    public synchronized CertificateEntity getActiveKey() {
        return certificateRepository.findFirstByActiveTrueOrderByCreatedAtDesc()
            .orElseGet(this::generateAndPersistKey);
    }

    /**
     * Startup self-check: proves the active signing key is actually usable before the
     * application accepts traffic. On a genuinely empty database this triggers
     * {@link #getActiveKey()} to generate the first key, which then passes the same
     * check trivially (it was just created with the current secret).
     * <p>
     * Without this, a protection-secret mismatch (e.g. a dev database reused after the
     * secret moved to a secret manager) would let startup succeed and {@code getActiveKey()}
     * succeed, only for every subsequent token issuance to fail at request time with no
     * signal anywhere. We deliberately do NOT regenerate a key here on failure — that would
     * mask the misconfiguration and orphan every already-issued token.
     */
    @Override
    public void afterPropertiesSet() {
        CertificateEntity active = getActiveKey();

        RSAPrivateKey privateKey;
        try {
            privateKey = toPrivateKey(active);
        } catch (Exception e) {
            throw new IllegalStateException(
                "startup check failed: the active signing key (keyId=" + active.getKeyId()
                    + ") could not be decrypted. The most likely cause is that '"
                    + KEY_PROTECTION_SECRET_PROPERTY
                    + "' does not match the secret that was used to encrypt it.", e);
        }

        RSAPublicKey publicKey;
        try {
            byte[] publicBytes = Base64.getDecoder().decode(active.getPublicKey());
            publicKey = (RSAPublicKey) KeyFactory.getInstance("RSA")
                .generatePublic(new X509EncodedKeySpec(publicBytes));
        } catch (Exception e) {
            throw new IllegalStateException(
                "startup check failed: the active signing key (keyId=" + active.getKeyId()
                    + ") has a public key that could not be parsed.", e);
        }

        if (!privateKey.getModulus().equals(publicKey.getModulus())) {
            throw new IllegalStateException(
                "startup check failed: the active signing key (keyId=" + active.getKeyId()
                    + ") is unusable — the decrypted private key's RSA modulus does not match "
                    + "the stored public key's modulus. This can also happen if '"
                    + KEY_PROTECTION_SECRET_PROPERTY + "' is misconfigured.");
        }
    }

    @Override
    public RSAKey toPublicJwk(CertificateEntity certificate) {
        try {
            byte[] publicBytes = Base64.getDecoder().decode(certificate.getPublicKey());
            RSAPublicKey publicKey = (RSAPublicKey) KeyFactory.getInstance("RSA")
                .generatePublic(new X509EncodedKeySpec(publicBytes));
            return new RSAKey.Builder(publicKey)
                .keyID(certificate.getKeyId())
                .keyUse(KeyUse.SIGNATURE)
                .build();
        } catch (Exception e) {
            throw new IllegalStateException("failed to build public jwk for key " + certificate.getKeyId(), e);
        }
    }

    @Override
    public List<RSAKey> getAllPublicJwks() {
        List<CertificateEntity> certificates = certificateRepository.findAllByOrderByCreatedAtAsc();
        if (certificates.isEmpty()) {
            // Belt-and-braces: afterPropertiesSet() already guarantees a key exists by the time
            // this service accepts traffic, but a JWKS endpoint returning an empty key set would
            // be indistinguishable from "verification is broken" for every caller, so fall back
            // to generating (or discovering another instance's freshly-generated) key rather than
            // ever publishing an empty set.
            certificates = List.of(getActiveKey());
        }
        return certificates.stream().map(this::toPublicJwk).toList();
    }

    @Override
    public RSAPrivateKey toPrivateKey(CertificateEntity certificate) {
        try {
            String decryptedPem = keyProtector.decrypt(certificate.getPrivateKeyEncrypted());
            byte[] privateBytes = Base64.getDecoder().decode(decryptedPem);
            return (RSAPrivateKey) KeyFactory.getInstance("RSA")
                .generatePrivate(new PKCS8EncodedKeySpec(privateBytes));
        } catch (Exception e) {
            throw new IllegalStateException("failed to load private key for " + certificate.getKeyId(), e);
        }
    }

    /**
     * Generates a new RSA-2048 key pair and persists it as the active key.
     * <p>
     * {@code getActiveKey()} is only {@code synchronized} within a single JVM: it does nothing
     * to stop two separate service instances from both finding no active key at startup and
     * both racing to generate and persist one, since each generates its own random {@code keyId}
     * (so the {@code key_id} uniqueness constraint never fires) and both rows would otherwise end
     * up {@code active = true}. The database-level partial unique index on {@code active} (see
     * {@code 003-create-certificate-table.yaml}) is what actually closes that race: whichever
     * instance's insert lands second gets a unique-constraint violation here. That instance must
     * not crash - {@link #afterPropertiesSet()} calls this via {@link #getActiveKey()} as part of
     * the startup self-check, and a thrown exception there fails the whole application's startup.
     * Instead, the loser discards its own freshly-generated (but never-persisted) key pair and
     * re-reads whichever key the winner just committed, so both instances converge on the same
     * active key.
     */
    private CertificateEntity generateAndPersistKey() {
        log.info("no active signing key found, generating a new rsa-2048 key pair");
        CertificateEntity certificate;
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            KeyPair keyPair = generator.generateKeyPair();

            String publicKeyBase64 = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
            String privateKeyBase64 = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());

            certificate = CertificateEntity.builder()
                .keyId(UUID.randomUUID().toString())
                .publicKey(publicKeyBase64)
                .privateKeyEncrypted(keyProtector.encrypt(privateKeyBase64))
                .active(true)
                .build();
        } catch (Exception e) {
            throw new IllegalStateException("failed to generate rsa signing key", e);
        }

        try {
            CertificateEntity saved = certificateRepository.save(certificate);
            log.info("generated and persisted new active signing key with keyId: {}", saved.getKeyId());
            return saved;
        } catch (DataIntegrityViolationException e) {
            log.warn("lost the race to persist a new active signing key to another instance; "
                + "reloading the key that instance committed instead of failing startup");
            return certificateRepository.findFirstByActiveTrueOrderByCreatedAtDesc()
                .orElseThrow(() -> new IllegalStateException(
                    "failed to generate rsa signing key: lost the insert race to another "
                        + "instance, but no active key could be found afterwards", e));
        }
    }
}
