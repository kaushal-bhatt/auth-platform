package com.authplatform.auth.service.impl;

import com.authplatform.auth.entity.CertificateEntity;
import com.authplatform.auth.repository.CertificateRepository;
import com.authplatform.auth.security.KeyProtector;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataIntegrityViolationException;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class KeysServiceImplTest {

    private CertificateRepository certificateRepository;
    private KeyProtector keyProtector;
    private KeysServiceImpl keysService;

    private String randomBase64Secret() {
        byte[] secretBytes = new byte[32];
        new SecureRandom().nextBytes(secretBytes);
        return Base64.getEncoder().encodeToString(secretBytes);
    }

    @BeforeEach
    void setUp() {
        certificateRepository = mock(CertificateRepository.class);
        when(certificateRepository.save(any(CertificateEntity.class)))
            .thenAnswer(invocation -> invocation.getArgument(0));

        keyProtector = new KeyProtector(randomBase64Secret());

        keysService = new KeysServiceImpl(certificateRepository, keyProtector);
    }

    @Test
    void getActiveKeyGeneratesAndPersistsWhenNoneExists() {
        when(certificateRepository.findFirstByActiveTrueOrderByCreatedAtDesc()).thenReturn(Optional.empty());

        CertificateEntity certificate = keysService.getActiveKey();

        assertThat(certificate.getKeyId()).isNotBlank();
        assertThat(certificate.isActive()).isTrue();
        verify(certificateRepository).save(any(CertificateEntity.class));
    }

    @Test
    void getActiveKeyReturnsExistingWithoutGeneratingANewOne() {
        CertificateEntity existing = CertificateEntity.builder()
            .keyId("existing-key")
            .active(true)
            .build();
        when(certificateRepository.findFirstByActiveTrueOrderByCreatedAtDesc()).thenReturn(Optional.of(existing));

        CertificateEntity certificate = keysService.getActiveKey();

        assertThat(certificate.getKeyId()).isEqualTo("existing-key");
        verify(certificateRepository, never()).save(any(CertificateEntity.class));
    }

    @Test
    void generatedKeyIsRsa2048Bits() {
        when(certificateRepository.findFirstByActiveTrueOrderByCreatedAtDesc()).thenReturn(Optional.empty());
        CertificateEntity certificate = keysService.getActiveKey();

        RSAPrivateKey privateKey = keysService.toPrivateKey(certificate);

        // auth-jwt-lib's JWKS client hard-rejects anything under 2048 bits; a silent drop
        // to 1024 here would break token verification platform-wide with a green build.
        assertThat(privateKey.getModulus().bitLength()).isEqualTo(2048);
    }

    @Test
    void publicAndPrivateKeysRoundTripASignature() throws Exception {
        when(certificateRepository.findFirstByActiveTrueOrderByCreatedAtDesc()).thenReturn(Optional.empty());
        CertificateEntity certificate = keysService.getActiveKey();

        RSAPrivateKey privateKey = keysService.toPrivateKey(certificate);
        RSAKey publicJwk = keysService.toPublicJwk(certificate);

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).build();
        byte[] signingInput = "test-signing-input".getBytes(StandardCharsets.UTF_8);

        Base64URL signature = new RSASSASigner(privateKey).sign(header, signingInput);
        boolean valid = new RSASSAVerifier(publicJwk).verify(header, signingInput, signature);

        assertThat(valid).isTrue();
        assertThat(publicJwk.getKeyID()).isEqualTo(certificate.getKeyId());
    }

    // -- Fix 2: startup lifecycle hook proves the active key is actually usable --------

    @Test
    void afterPropertiesSetSucceedsAndGeneratesFirstKeyOnAGenuinelyEmptyDatabase() {
        // the expected path: nothing exists yet, so getActiveKey() creates the first key
        // during the startup check, and that freshly-created key must pass the same
        // usability assertion trivially (it was just encrypted with the current secret).
        when(certificateRepository.findFirstByActiveTrueOrderByCreatedAtDesc()).thenReturn(Optional.empty());

        keysService.afterPropertiesSet();

        verify(certificateRepository).save(any(CertificateEntity.class));
    }

    @Test
    void afterPropertiesSetSucceedsWhenExistingActiveKeyIsUsable() {
        when(certificateRepository.findFirstByActiveTrueOrderByCreatedAtDesc()).thenReturn(Optional.empty());
        CertificateEntity generated = keysService.getActiveKey();
        reset(certificateRepository);
        when(certificateRepository.findFirstByActiveTrueOrderByCreatedAtDesc()).thenReturn(Optional.of(generated));

        keysService.afterPropertiesSet();

        verify(certificateRepository, never()).save(any(CertificateEntity.class));
    }

    @Test
    void afterPropertiesSetFailsFastWhenActiveKeyWasEncryptedUnderADifferentSecret() {
        // simulates the dev->prod path Fix 1 creates: the row survives but the protection
        // secret changed, so the stored ciphertext can no longer be decrypted.
        KeyProtector differentKeyProtector = new KeyProtector(randomBase64Secret());
        KeysServiceImpl generatingService = new KeysServiceImpl(certificateRepository, differentKeyProtector);
        when(certificateRepository.findFirstByActiveTrueOrderByCreatedAtDesc()).thenReturn(Optional.empty());
        CertificateEntity generatedUnderOtherSecret = generatingService.getActiveKey();

        reset(certificateRepository);
        when(certificateRepository.findFirstByActiveTrueOrderByCreatedAtDesc())
            .thenReturn(Optional.of(generatedUnderOtherSecret));

        assertThatThrownBy(() -> keysService.afterPropertiesSet())
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("auth-platform.issuer.key-protection-secret")
            .hasMessageNotContainingAny(generatedUnderOtherSecret.getPrivateKeyEncrypted());
    }

    @Test
    void afterPropertiesSetFailsFastWhenStoredPublicKeyDoesNotMatchPrivateKey() {
        when(certificateRepository.findFirstByActiveTrueOrderByCreatedAtDesc()).thenReturn(Optional.empty());
        CertificateEntity generated = keysService.getActiveKey();

        // corrupt the row so the public key belongs to an unrelated key pair, simulating
        // a manually-edited / corrupted database row.
        CertificateEntity otherKeyCertificate = new KeysServiceImpl(certificateRepository, keyProtector)
            .getActiveKey();
        CertificateEntity corrupted = CertificateEntity.builder()
            .keyId(generated.getKeyId())
            .publicKey(otherKeyCertificate.getPublicKey())
            .privateKeyEncrypted(generated.getPrivateKeyEncrypted())
            .active(true)
            .build();

        reset(certificateRepository);
        when(certificateRepository.findFirstByActiveTrueOrderByCreatedAtDesc()).thenReturn(Optional.of(corrupted));

        assertThatThrownBy(() -> keysService.afterPropertiesSet())
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("modulus");
    }

    // -- Task 17: multi-instance race on the partial unique active-key index -------------------

    /**
     * Simulates the multi-instance race the {@code idx_certificate_single_active_key} partial
     * unique index (003-create-certificate-table.yaml) is meant to close: two instances both
     * find no active key and both attempt to persist their own freshly-generated one as active.
     * Whichever insert lands second gets a {@link DataIntegrityViolationException} from
     * postgres. That instance must not propagate the exception (which would fail
     * {@code afterPropertiesSet()} and crash the whole application at startup) - it must instead
     * discard its own generated key pair and re-read the key the winner already committed.
     */
    @Test
    void generateAndPersistKeyRecoversWhenItLosesTheInsertRaceInsteadOfCrashing() {
        CertificateEntity winnersKey = CertificateEntity.builder()
            .keyId("winning-instance-key")
            .active(true)
            .build();

        when(certificateRepository.findFirstByActiveTrueOrderByCreatedAtDesc())
            // first call (inside getActiveKey()): nothing exists yet, so we attempt to generate
            .thenReturn(Optional.empty())
            // second call (recovery path inside generateAndPersistKey() after losing the race)
            .thenReturn(Optional.of(winnersKey));
        when(certificateRepository.save(any(CertificateEntity.class)))
            .thenThrow(new DataIntegrityViolationException(
                "duplicate key value violates unique constraint \"idx_certificate_single_active_key\""));

        CertificateEntity result = keysService.getActiveKey();

        assertThat(result).isEqualTo(winnersKey);
    }

    /**
     * If losing the race also fails to find any active key afterwards (a scenario that should
     * be unreachable in practice, since the winner's commit is what caused our insert to fail
     * in the first place), the failure must still surface as a clear {@link IllegalStateException}
     * rather than an opaque {@link DataIntegrityViolationException} or NPE.
     */
    @Test
    void generateAndPersistKeyFailsClearlyIfRecoveryAlsoFindsNoActiveKey() {
        when(certificateRepository.findFirstByActiveTrueOrderByCreatedAtDesc())
            .thenReturn(Optional.empty());
        when(certificateRepository.save(any(CertificateEntity.class)))
            .thenThrow(new DataIntegrityViolationException("duplicate key value"));

        assertThatThrownBy(() -> keysService.getActiveKey())
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("lost the insert race");
    }

    // -- Task 17: publishing all stored keys, not just the active one --------------------------

    @Test
    void getAllPublicJwksReturnsEveryStoredCertificatesPublicKey() {
        when(certificateRepository.findFirstByActiveTrueOrderByCreatedAtDesc()).thenReturn(Optional.empty());
        CertificateEntity active = keysService.getActiveKey();
        CertificateEntity rotatedOut = new KeysServiceImpl(certificateRepository, keyProtector).getActiveKey();

        when(certificateRepository.findAllByOrderByCreatedAtAsc()).thenReturn(List.of(rotatedOut, active));

        List<RSAKey> publicJwks = keysService.getAllPublicJwks();

        assertThat(publicJwks).extracting(RSAKey::getKeyID)
            .containsExactly(rotatedOut.getKeyId(), active.getKeyId());
        assertThat(publicJwks).allSatisfy(jwk -> assertThat(jwk.isPrivate()).isFalse());
    }

    @Test
    void getAllPublicJwksFallsBackToGeneratingAKeyWhenTheTableIsEmpty() {
        when(certificateRepository.findAllByOrderByCreatedAtAsc()).thenReturn(List.of());
        when(certificateRepository.findFirstByActiveTrueOrderByCreatedAtDesc()).thenReturn(Optional.empty());

        List<RSAKey> publicJwks = keysService.getAllPublicJwks();

        assertThat(publicJwks).hasSize(1);
        verify(certificateRepository).save(any(CertificateEntity.class));
    }
}
