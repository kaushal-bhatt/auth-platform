package com.authplatform.auth.service.impl;

import com.authplatform.auth.config.WebAuthnProperties;
import com.authplatform.auth.dto.PasskeyLoginCompleteRequest;
import com.authplatform.auth.dto.PasskeyLoginInitResponse;
import com.authplatform.auth.entity.PasskeyCredentialEntity;
import com.authplatform.auth.entity.UserEntity;
import com.authplatform.auth.exception.CustomException;
import com.authplatform.auth.repository.PasskeyCredentialRepository;
import com.authplatform.auth.repository.UserRepository;
import com.authplatform.auth.service.TokenService;
import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.converter.AttestedCredentialDataConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.authenticator.EC2COSEKey;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Covers exactly what this codebase owns per the Task 15 brief's scope note: unknown email / no
 * registered passkeys / email normalisation on {@code initLogin}; challenge and credential
 * ownership, malformed-assertion-input mapping to a clean status, and sign-count regression on
 * {@code completeLogin} - not the happy path of a genuinely valid assertion signature, which is
 * webauthn4j's own well-tested territory (mirrors {@code PasskeyRegistrationServiceImplTest}'s
 * scope note for the same reason).
 * <p>
 * {@link #realAttestedCredentialDataBase64()} builds a structurally real {@link
 * AttestedCredentialData} (real EC keypair, real CBOR encoding via the actual {@link
 * AttestedCredentialDataConverter}) purely so a test can get past this service's
 * {@code attestedCredentialDataConverter.convert(...)} call on stored (trusted, previously
 * validated) data and reach {@code WebAuthnManager#validate}. It does not sign anything with that
 * key and never attempts to produce a valid assertion signature - the "malformed assertion" tests
 * still exercise genuinely malformed {@code authenticatorData}/{@code clientDataJSON}/
 * {@code signature} bytes, which is what this class actually owns.
 */
class PasskeyLoginFlowServiceImplTest {

    /**
     * Mirrors {@code PasskeyLoginFlowServiceImpl.PASSKEY_AUTHENTICATION_FAILED}, which is private.
     * Spelling it out here rather than exposing the constant means a change to the wire message has
     * to be made deliberately in two places.
     */
    private static final String PASSKEY_AUTHENTICATION_FAILED = "passkey authentication failed";

    private PasskeyChallengeHelper passkeyChallengeHelper;
    private PasskeyCredentialRepository passkeyCredentialRepository;
    private UserRepository userRepository;
    private TokenService tokenService;
    private WebAuthnProperties webAuthnProperties;
    private AttestedCredentialDataConverter attestedCredentialDataConverter;
    private PasskeyLoginFlowServiceImpl service;

    @BeforeEach
    void setUp() {
        passkeyChallengeHelper = mock(PasskeyChallengeHelper.class);
        passkeyCredentialRepository = mock(PasskeyCredentialRepository.class);
        userRepository = mock(UserRepository.class);
        tokenService = mock(TokenService.class);
        webAuthnProperties = new WebAuthnProperties();
        webAuthnProperties.setRelyingPartyId("localhost");
        webAuthnProperties.setOrigin("http://localhost:3000");
        attestedCredentialDataConverter = new AttestedCredentialDataConverter(new ObjectConverter());

        service = new PasskeyLoginFlowServiceImpl(
            passkeyChallengeHelper,
            passkeyCredentialRepository,
            userRepository,
            tokenService,
            webAuthnProperties,
            WebAuthnManager.createNonStrictWebAuthnManager(),
            attestedCredentialDataConverter);
    }

    private String realAttestedCredentialDataBase64() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        EC2COSEKey coseKey = EC2COSEKey.create((ECPublicKey) keyPair.getPublic());
        AttestedCredentialData attestedCredentialData =
            new AttestedCredentialData(AAGUID.ZERO, "cred-1".getBytes(), coseKey);
        return Base64.getEncoder().encodeToString(attestedCredentialDataConverter.convert(attestedCredentialData));
    }

    @Test
    void initLoginRejectsUnknownEmail() {
        when(userRepository.findByEmail("nobody@example.com")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.initLogin("nobody@example.com"))
            .isInstanceOf(CustomException.class);
    }

    @Test
    void initLoginRejectsUserWithNoPasskeys() {
        UserEntity user = UserEntity.builder()
            .id(3L).email("no-passkeys@example.com").passwordHash("hash")
            .createdAt(Instant.now()).updatedAt(Instant.now()).build();
        when(userRepository.findByEmail("no-passkeys@example.com")).thenReturn(Optional.of(user));
        when(passkeyCredentialRepository.findByUserId(3L)).thenReturn(List.of());

        assertThatThrownBy(() -> service.initLogin("no-passkeys@example.com"))
            .isInstanceOf(CustomException.class);
    }

    /**
     * Pins the user-enumeration mitigation: "unknown email" and "user has no passkeys" must be
     * indistinguishable from the response alone, mirroring {@code LoginServiceImpl}'s existing
     * uniform-failure pattern for password login.
     */
    @Test
    void initLoginUnknownEmailAndNoPasskeysProduceTheIdenticalMessage() {
        UserEntity user = UserEntity.builder()
            .id(5L).email("no-passkeys-2@example.com").passwordHash("hash")
            .createdAt(Instant.now()).updatedAt(Instant.now()).build();
        when(userRepository.findByEmail("no-passkeys-2@example.com")).thenReturn(Optional.of(user));
        when(passkeyCredentialRepository.findByUserId(5L)).thenReturn(List.of());
        when(userRepository.findByEmail("nobody-2@example.com")).thenReturn(Optional.empty());

        String noPasskeysMessage = catchCustomExceptionMessage(() -> service.initLogin("no-passkeys-2@example.com"));
        String unknownEmailMessage = catchCustomExceptionMessage(() -> service.initLogin("nobody-2@example.com"));

        assertThat(noPasskeysMessage).isEqualTo(unknownEmailMessage);
    }

    private String catchCustomExceptionMessage(Runnable runnable) {
        try {
            runnable.run();
        } catch (CustomException e) {
            return e.getMessage();
        }
        throw new AssertionError("expected a CustomException to be thrown");
    }

    @Test
    void initLoginReturnsAllowedCredentialIds() {
        UserEntity user = UserEntity.builder()
            .id(4L).email("has-passkey@example.com").passwordHash("hash")
            .createdAt(Instant.now()).updatedAt(Instant.now()).build();
        PasskeyCredentialEntity credential = PasskeyCredentialEntity.builder()
            .userId(4L).credentialId("cred-1").attestedCredentialData("irrelevant")
            .signCount(0).createdAt(Instant.now()).build();
        when(userRepository.findByEmail("has-passkey@example.com")).thenReturn(Optional.of(user));
        when(passkeyCredentialRepository.findByUserId(4L)).thenReturn(List.of(credential));
        when(passkeyChallengeHelper.issueChallenge(4L)).thenReturn(new DefaultChallenge("challenge-value"));

        PasskeyLoginInitResponse response = service.initLogin("has-passkey@example.com");

        assertThat(response.allowCredentialIds()).containsExactly("cred-1");
        assertThat(response.rpId()).isEqualTo("localhost");
    }

    /**
     * Pins that every email lookup goes through {@code EmailNormalizer}: a user stored
     * lower-cased (as Task 7's registration always stores) must still be found - and able to log
     * in via passkey - when the caller supplies a mixed-case variant of the same address.
     */
    @Test
    void initLoginNormalisesEmailBeforeLookup() {
        UserEntity user = UserEntity.builder()
            .id(6L).email("registered@example.com").passwordHash("hash")
            .createdAt(Instant.now()).updatedAt(Instant.now()).build();
        PasskeyCredentialEntity credential = PasskeyCredentialEntity.builder()
            .userId(6L).credentialId("cred-6").attestedCredentialData("irrelevant")
            .signCount(0).createdAt(Instant.now()).build();
        when(userRepository.findByEmail("registered@example.com")).thenReturn(Optional.of(user));
        when(passkeyCredentialRepository.findByUserId(6L)).thenReturn(List.of(credential));
        when(passkeyChallengeHelper.issueChallenge(6L)).thenReturn(new DefaultChallenge("challenge-value"));

        PasskeyLoginInitResponse response = service.initLogin("REGISTERED@Example.com  ");

        assertThat(response.allowCredentialIds()).containsExactly("cred-6");
        verify(userRepository).findByEmail(eq("registered@example.com"));
    }

    @Test
    void completeLoginRejectsUnknownCredential() {
        when(passkeyChallengeHelper.consumeChallenge("some-challenge")).thenReturn(4L);
        when(passkeyCredentialRepository.findByCredentialId("unknown-cred")).thenReturn(Optional.empty());

        PasskeyLoginCompleteRequest request = new PasskeyLoginCompleteRequest(
            "some-challenge",
            "unknown-cred",
            Base64.getUrlEncoder().encodeToString("garbage".getBytes()),
            Base64.getUrlEncoder().encodeToString("garbage".getBytes()),
            Base64.getUrlEncoder().encodeToString("garbage".getBytes()));

        assertThatThrownBy(() -> service.completeLogin(request))
            .isInstanceOf(CustomException.class);
    }

    /**
     * Pins security point 2 (challenge/credential ownership): a credential that genuinely exists
     * but belongs to a DIFFERENT user than the one the challenge was issued to must be rejected,
     * not silently accepted because a row was found at all.
     */
    @Test
    void completeLoginRejectsCredentialOwnedByADifferentUserThanTheChallenge() {
        when(passkeyChallengeHelper.consumeChallenge("some-challenge")).thenReturn(4L);
        PasskeyCredentialEntity credentialOwnedByUser99 = PasskeyCredentialEntity.builder()
            .userId(99L).credentialId("cred-owned-by-99").attestedCredentialData("irrelevant")
            .signCount(0).createdAt(Instant.now()).build();
        when(passkeyCredentialRepository.findByCredentialId("cred-owned-by-99"))
            .thenReturn(Optional.of(credentialOwnedByUser99));

        PasskeyLoginCompleteRequest request = new PasskeyLoginCompleteRequest(
            "some-challenge",
            "cred-owned-by-99",
            Base64.getUrlEncoder().encodeToString("garbage".getBytes()),
            Base64.getUrlEncoder().encodeToString("garbage".getBytes()),
            Base64.getUrlEncoder().encodeToString("garbage".getBytes()));

        assertThatThrownBy(() -> service.completeLogin(request))
            .isInstanceOf(CustomException.class)
            .hasMessage(PASSKEY_AUTHENTICATION_FAILED);
    }

    /**
     * Pins the uniform-failure property of {@code completeLogin}: every rejection after the
     * challenge is consumed must be textually identical, so an anonymous caller cannot tell an
     * unknown credential id from a credential owned by somebody else, from malformed input, from a
     * regressed sign count, from a user row that has since been deleted. This method used to
     * return four distinct 401 messages, including {@code "user no longer exists"}.
     */
    @Test
    void completeLoginFailuresAllShareTheIdenticalStatusAndMessage() throws Exception {
        // (a) unknown credential id
        when(passkeyChallengeHelper.consumeChallenge("challenge-a")).thenReturn(70L);
        when(passkeyCredentialRepository.findByCredentialId("nope")).thenReturn(Optional.empty());

        // (b) credential owned by a different user than the challenge
        when(passkeyChallengeHelper.consumeChallenge("challenge-b")).thenReturn(70L);
        when(passkeyCredentialRepository.findByCredentialId("cred-other")).thenReturn(Optional.of(
            PasskeyCredentialEntity.builder()
                .userId(999L).credentialId("cred-other").attestedCredentialData("irrelevant")
                .signCount(0).createdAt(Instant.now()).build()));

        // (c) malformed assertion bytes that are nonetheless valid base64
        String storedData = realAttestedCredentialDataBase64();
        when(passkeyChallengeHelper.consumeChallenge("challenge-c")).thenReturn(70L);
        when(passkeyCredentialRepository.findByCredentialId("cred-c")).thenReturn(Optional.of(
            PasskeyCredentialEntity.builder()
                .userId(70L).credentialId("cred-c").attestedCredentialData(storedData)
                .signCount(0).createdAt(Instant.now()).build()));

        // (d) malformed base64url
        when(passkeyChallengeHelper.consumeChallenge("challenge-d")).thenReturn(70L);
        when(passkeyCredentialRepository.findByCredentialId("cred-d")).thenReturn(Optional.of(
            PasskeyCredentialEntity.builder()
                .userId(70L).credentialId("cred-d").attestedCredentialData(storedData)
                .signCount(0).createdAt(Instant.now()).build()));

        List<CustomException> failures = List.of(
            catchCustomException(() -> service.completeLogin(requestFor("challenge-a", "nope", "Z2FyYmFnZQ"))),
            catchCustomException(() -> service.completeLogin(requestFor("challenge-b", "cred-other", "Z2FyYmFnZQ"))),
            catchCustomException(() -> service.completeLogin(requestFor("challenge-c", "cred-c", "Z2FyYmFnZQ"))),
            catchCustomException(() -> service.completeLogin(requestFor("challenge-d", "cred-d", "###"))),
            catchCustomException(() -> service.rejectIfSignCountRegressed(3L, 5L)));

        assertThat(failures).allSatisfy(failure -> {
            assertThat(failure.getStatus()).isEqualTo(401);
            assertThat(failure.getMessage()).isEqualTo(PASSKEY_AUTHENTICATION_FAILED);
        });
    }

    /**
     * Fix 4: {@code Base64.getUrlDecoder().decode} throws {@link IllegalArgumentException}, which is
     * NOT one of the two exceptions the {@code webAuthnManager.validate} guard catches. Decoding
     * used to happen outside that guard, so this input escaped as an HTTP 500 with a full stack
     * trace logged at ERROR - unauthenticated-reachable and therefore repeatable without limit.
     * It must now be the same clean 401 as garbage-but-decodable input.
     */
    @Test
    void completeLoginRejectsMalformedBase64WithoutServerError() throws Exception {
        when(passkeyChallengeHelper.consumeChallenge("some-challenge")).thenReturn(8L);
        PasskeyCredentialEntity storedCredential = PasskeyCredentialEntity.builder()
            .userId(8L).credentialId("cred-8").attestedCredentialData(realAttestedCredentialDataBase64())
            .signCount(0).createdAt(Instant.now()).build();
        when(passkeyCredentialRepository.findByCredentialId("cred-8")).thenReturn(Optional.of(storedCredential));

        // "###" is not valid base64url in any field
        for (PasskeyLoginCompleteRequest request : List.of(
            new PasskeyLoginCompleteRequest("some-challenge", "cred-8", "###", "Z2FyYmFnZQ", "Z2FyYmFnZQ"),
            new PasskeyLoginCompleteRequest("some-challenge", "cred-8", "Z2FyYmFnZQ", "###", "Z2FyYmFnZQ"),
            new PasskeyLoginCompleteRequest("some-challenge", "cred-8", "Z2FyYmFnZQ", "Z2FyYmFnZQ", "###"))) {

            CustomException failure = catchCustomException(() -> service.completeLogin(request));

            assertThat(failure.getStatus()).isEqualTo(401);
            assertThat(failure.getMessage()).isEqualTo(PASSKEY_AUTHENTICATION_FAILED);
        }
    }

    private static PasskeyLoginCompleteRequest requestFor(String challenge, String credentialId, String signature) {
        return new PasskeyLoginCompleteRequest(challenge, credentialId, "Z2FyYmFnZQ", "Z2FyYmFnZQ", signature);
    }

    private CustomException catchCustomException(Runnable runnable) {
        try {
            runnable.run();
        } catch (CustomException e) {
            return e;
        }
        throw new AssertionError("expected a CustomException to be thrown");
    }

    /**
     * Pins the two-exception catch: garbage (but validly base64-encoded)
     * {@code authenticatorData}/{@code clientDataJSON}/{@code signature} must map to a clean
     * {@link CustomException}, not an uncaught {@code DataConversionException} that would surface
     * as a 500 via {@code GlobalExceptionHandler}'s catch-all.
     */
    @Test
    void completeLoginRejectsMalformedAssertionWithoutServerError() throws Exception {
        when(passkeyChallengeHelper.consumeChallenge("some-challenge")).thenReturn(7L);
        PasskeyCredentialEntity storedCredential = PasskeyCredentialEntity.builder()
            .userId(7L).credentialId("cred-7").attestedCredentialData(realAttestedCredentialDataBase64())
            .signCount(0).createdAt(Instant.now()).build();
        when(passkeyCredentialRepository.findByCredentialId("cred-7")).thenReturn(Optional.of(storedCredential));

        PasskeyLoginCompleteRequest request = new PasskeyLoginCompleteRequest(
            "some-challenge",
            "cred-7",
            Base64.getUrlEncoder().encodeToString("not-real-authenticator-data".getBytes()),
            Base64.getUrlEncoder().encodeToString("not-real-client-data-json".getBytes()),
            Base64.getUrlEncoder().encodeToString("not-a-real-signature".getBytes()));

        assertThatThrownBy(() -> service.completeLogin(request))
            .isInstanceOf(CustomException.class)
            .extracting(e -> ((CustomException) e).getStatus())
            .isEqualTo(401);
    }

    @Test
    void rejectIfSignCountRegressedRejectsANonZeroCountThatDidNotIncrease() {
        assertThatThrownBy(() -> service.rejectIfSignCountRegressed(3L, 5L))
            .isInstanceOf(CustomException.class);

        assertThatThrownBy(() -> service.rejectIfSignCountRegressed(5L, 5L))
            .isInstanceOf(CustomException.class);
    }

    @Test
    void rejectIfSignCountRegressedAllowsAnIncreasedCount() {
        assertThatCode(() -> service.rejectIfSignCountRegressed(6L, 5L)).doesNotThrowAnyException();
    }

    /**
     * Pins the deliberate "zero means no counter support" carve-out: authenticators that always
     * report a signature counter of {@code 0} (common for passkeys) must not be rejected as a
     * regression even though {@code 0 <= storedSignCount} would otherwise fail the check.
     */
    @Test
    void rejectIfSignCountRegressedAllowsRepeatedZeroForCounterlessAuthenticators() {
        assertThatCode(() -> service.rejectIfSignCountRegressed(0L, 999L)).doesNotThrowAnyException();
    }
}
