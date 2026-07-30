package com.authplatform.auth.security;

import org.junit.jupiter.api.Test;

import javax.crypto.AEADBadTagException;
import java.security.SecureRandom;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class KeyProtectorTest {

    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH_BYTES = 16;

    private String randomBase64Secret(int lengthBytes) {
        byte[] bytes = new byte[lengthBytes];
        new SecureRandom().nextBytes(bytes);
        return Base64.getEncoder().encodeToString(bytes);
    }

    @Test
    void constructorRejectsSecretWithInvalidDecodedLength() {
        String tenByteSecret = randomBase64Secret(10);

        assertThatThrownBy(() -> new KeyProtector(tenByteSecret))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("auth-platform.issuer.key-protection-secret")
            .hasMessageContaining("exactly 32");
    }

    @Test
    void constructorRejectsNullSecret() {
        assertThatThrownBy(() -> new KeyProtector(null))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("auth-platform.issuer.key-protection-secret");
    }

    @Test
    void constructorRejectsBlankSecret() {
        assertThatThrownBy(() -> new KeyProtector("   "))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("auth-platform.issuer.key-protection-secret");
    }

    @Test
    void constructorRejectsNonBase64Secret() {
        assertThatThrownBy(() -> new KeyProtector("not-valid-base64!!!***"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("auth-platform.issuer.key-protection-secret");
    }

    // -- Fix 3: only exactly 32 decoded bytes (AES-256) is accepted --------------------

    @Test
    void constructorRejects16ByteSecret() {
        String sixteenByteSecret = randomBase64Secret(16);

        assertThatThrownBy(() -> new KeyProtector(sixteenByteSecret))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("auth-platform.issuer.key-protection-secret")
            .hasMessageContaining("exactly 32");
    }

    @Test
    void constructorRejects24ByteSecret() {
        String twentyFourByteSecret = randomBase64Secret(24);

        assertThatThrownBy(() -> new KeyProtector(twentyFourByteSecret))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("auth-platform.issuer.key-protection-secret")
            .hasMessageContaining("exactly 32");
    }

    @Test
    void constructorAccepts32ByteSecret() {
        String thirtyTwoByteSecret = randomBase64Secret(32);

        KeyProtector keyProtector = new KeyProtector(thirtyTwoByteSecret);
        String plaintext = "32-byte-secret-is-accepted";

        assertThat(keyProtector.decrypt(keyProtector.encrypt(plaintext))).isEqualTo(plaintext);
    }

    // -- Fix 4: incidental whitespace around an otherwise-correct secret is tolerated --

    @Test
    void constructorAcceptsSecretWithTrailingNewline() {
        String secret = randomBase64Secret(32);

        // a trailing newline is trivially introduced by `echo`, a k8s secret file mount,
        // or YAML block scalar folding; it must not be treated as an invalid secret.
        KeyProtector keyProtector = new KeyProtector(secret + "\n");
        String plaintext = "value-should-round-trip-fine";

        String ciphertext = keyProtector.encrypt(plaintext);

        assertThat(keyProtector.decrypt(ciphertext)).isEqualTo(plaintext);
    }

    @Test
    void encryptThenDecryptRoundTripsExactPlaintext() {
        KeyProtector keyProtector = new KeyProtector(randomBase64Secret(32));
        String plaintext = "super-secret-rsa-private-key-pem-bytes";

        String ciphertext = keyProtector.encrypt(plaintext);
        String decrypted = keyProtector.decrypt(ciphertext);

        assertThat(decrypted).isEqualTo(plaintext);
    }

    @Test
    void encryptingSamePlaintextTwiceYieldsDifferentCiphertexts() {
        KeyProtector keyProtector = new KeyProtector(randomBase64Secret(32));
        String plaintext = "same-plaintext-every-time";

        String ciphertext1 = keyProtector.encrypt(plaintext);
        String ciphertext2 = keyProtector.encrypt(plaintext);

        assertThat(ciphertext1).isNotEqualTo(ciphertext2);
    }

    // -- Fix 5.5: framing — IV length is exactly 12 bytes and is fresh per call --------

    @Test
    void framingIsIvPrependedToCiphertextAndFreshPerCall() {
        KeyProtector keyProtector = new KeyProtector(randomBase64Secret(32));
        String plaintext = "framing-check-plaintext";
        int expectedPlaintextAndTagLength = plaintext.getBytes(java.nio.charset.StandardCharsets.UTF_8).length
            + GCM_TAG_LENGTH_BYTES;

        byte[] combined1 = Base64.getDecoder().decode(keyProtector.encrypt(plaintext));
        byte[] combined2 = Base64.getDecoder().decode(keyProtector.encrypt(plaintext));

        assertThat(combined1.length).isEqualTo(GCM_IV_LENGTH + expectedPlaintextAndTagLength);
        assertThat(combined2.length).isEqualTo(GCM_IV_LENGTH + expectedPlaintextAndTagLength);

        byte[] iv1 = java.util.Arrays.copyOfRange(combined1, 0, GCM_IV_LENGTH);
        byte[] iv2 = java.util.Arrays.copyOfRange(combined2, 0, GCM_IV_LENGTH);
        assertThat(iv1).isNotEqualTo(iv2);
    }

    // -- Fix 5.6: pin that GCM authentication (not some unrelated failure) fired -------

    @Test
    void tamperingWithCiphertextByteCausesDecryptionToThrowWithAeadBadTagRootCause() {
        KeyProtector keyProtector = new KeyProtector(randomBase64Secret(32));
        String plaintext = "another-secret-value";
        String ciphertext = keyProtector.encrypt(plaintext);

        byte[] combined = Base64.getDecoder().decode(ciphertext);
        // flip a bit well past the IV (first 12 bytes) so it hits the actual ciphertext/tag.
        int tamperIndex = combined.length - 1;
        combined[tamperIndex] = (byte) (combined[tamperIndex] ^ 0xFF);
        String tamperedCiphertext = Base64.getEncoder().encodeToString(combined);

        assertThatThrownBy(() -> keyProtector.decrypt(tamperedCiphertext))
            .isInstanceOf(IllegalStateException.class)
            .hasCauseInstanceOf(AEADBadTagException.class);
    }

    // -- Fix 5.4: IV itself is covered by authentication --------------------------------

    @Test
    void tamperingWithIvByteCausesDecryptionToFail() {
        KeyProtector keyProtector = new KeyProtector(randomBase64Secret(32));
        String plaintext = "iv-is-authenticated-too";
        String ciphertext = keyProtector.encrypt(plaintext);

        byte[] combined = Base64.getDecoder().decode(ciphertext);
        // flip the very first byte, which lives inside the 12-byte IV.
        combined[0] = (byte) (combined[0] ^ 0xFF);
        String tamperedCiphertext = Base64.getEncoder().encodeToString(combined);

        assertThatThrownBy(() -> keyProtector.decrypt(tamperedCiphertext))
            .isInstanceOf(IllegalStateException.class)
            .hasCauseInstanceOf(AEADBadTagException.class);
    }

    // -- Fix 5.1: a value encrypted under one secret must not decrypt under another ----

    @Test
    void valueEncryptedUnderOneSecretFailsToDecryptUnderADifferentSecret() {
        KeyProtector protectorA = new KeyProtector(randomBase64Secret(32));
        KeyProtector protectorB = new KeyProtector(randomBase64Secret(32));
        String ciphertext = protectorA.encrypt("cross-secret-isolation-check");

        assertThatThrownBy(() -> protectorB.decrypt(ciphertext))
            .isInstanceOf(IllegalStateException.class)
            .hasCauseInstanceOf(AEADBadTagException.class);
    }

    // -- Fix 5.2: a fresh instance built from the same secret string must decrypt fine -

    @Test
    void separateInstanceConstructedFromSameSecretStringDecryptsSuccessfully() {
        String secret = randomBase64Secret(32);
        KeyProtector encryptingInstance = new KeyProtector(secret);
        String plaintext = "should-survive-a-restart";
        String ciphertext = encryptingInstance.encrypt(plaintext);

        KeyProtector freshInstanceAfterSimulatedRestart = new KeyProtector(secret);

        assertThat(freshInstanceAfterSimulatedRestart.decrypt(ciphertext)).isEqualTo(plaintext);
    }

    // -- Fix 5.3: malformed / truncated stored ciphertext surfaces as a clean exception,
    //             never a wrong plaintext and never an unchecked exception escaping ----

    @Test
    void decryptingEmptyStringSurfacesAsCleanException() {
        KeyProtector keyProtector = new KeyProtector(randomBase64Secret(32));

        assertThatThrownBy(() -> keyProtector.decrypt(""))
            .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void decryptingValueShorterThanIvSurfacesAsCleanException() {
        KeyProtector keyProtector = new KeyProtector(randomBase64Secret(32));
        String tooShort = Base64.getEncoder().encodeToString(new byte[5]);

        assertThatThrownBy(() -> keyProtector.decrypt(tooShort))
            .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void decryptingValueOfExactlyIvLengthSurfacesAsCleanException() {
        KeyProtector keyProtector = new KeyProtector(randomBase64Secret(32));
        String ivOnlyNoCiphertextOrTag = Base64.getEncoder().encodeToString(new byte[GCM_IV_LENGTH]);

        assertThatThrownBy(() -> keyProtector.decrypt(ivOnlyNoCiphertextOrTag))
            .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void decryptingNonBase64ValueSurfacesAsCleanException() {
        KeyProtector keyProtector = new KeyProtector(randomBase64Secret(32));

        assertThatThrownBy(() -> keyProtector.decrypt("not-valid-base64!!!***"))
            .isInstanceOf(IllegalStateException.class);
    }
}
