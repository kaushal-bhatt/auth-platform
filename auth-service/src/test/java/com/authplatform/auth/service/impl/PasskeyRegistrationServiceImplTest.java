package com.authplatform.auth.service.impl;

import com.authplatform.auth.config.WebAuthnProperties;
import com.authplatform.auth.dto.PasskeyRegisterCompleteRequest;
import com.authplatform.auth.dto.PasskeyRegisterInitResponse;
import com.authplatform.auth.entity.UserEntity;
import com.authplatform.auth.exception.CustomException;
import com.authplatform.auth.repository.PasskeyCredentialRepository;
import com.authplatform.auth.repository.UserRepository;
import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.converter.AttestedCredentialDataConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class PasskeyRegistrationServiceImplTest {

    private PasskeyChallengeHelper passkeyChallengeHelper;
    private PasskeyCredentialRepository passkeyCredentialRepository;
    private UserRepository userRepository;
    private WebAuthnProperties webAuthnProperties;
    private PasskeyRegistrationServiceImpl service;

    @BeforeEach
    void setUp() {
        passkeyChallengeHelper = mock(PasskeyChallengeHelper.class);
        passkeyCredentialRepository = mock(PasskeyCredentialRepository.class);
        userRepository = mock(UserRepository.class);
        webAuthnProperties = new WebAuthnProperties();
        webAuthnProperties.setRelyingPartyId("localhost");
        webAuthnProperties.setRelyingPartyName("Auth Platform");
        webAuthnProperties.setOrigin("http://localhost:3000");

        service = new PasskeyRegistrationServiceImpl(
            passkeyChallengeHelper,
            passkeyCredentialRepository,
            userRepository,
            webAuthnProperties,
            WebAuthnManager.createNonStrictWebAuthnManager(),
            new AttestedCredentialDataConverter(new ObjectConverter()));
    }

    @Test
    void initRegistrationReturnsChallengeAndRpInfoForKnownUser() {
        UserEntity user = UserEntity.builder()
            .id(9L).email("user@example.com").passwordHash("hash")
            .createdAt(Instant.now()).updatedAt(Instant.now()).build();
        when(userRepository.findById(9L)).thenReturn(Optional.of(user));
        when(passkeyChallengeHelper.issueChallenge(9L)).thenReturn(new DefaultChallenge("challenge-bytes-here"));

        PasskeyRegisterInitResponse response = service.initRegistration(9L);

        assertThat(response.userId()).isEqualTo("9");
        assertThat(response.userName()).isEqualTo("user@example.com");
        assertThat(response.rpId()).isEqualTo("localhost");
        assertThat(response.challenge()).isNotBlank();
    }

    @Test
    void initRegistrationRejectsUnknownUser() {
        when(userRepository.findById(99L)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.initRegistration(99L))
            .isInstanceOf(CustomException.class);
    }

    @Test
    void completeRegistrationRejectsChallengeOwnedByAnotherUser() {
        when(passkeyChallengeHelper.consumeChallenge("some-challenge")).thenReturn(123L);

        PasskeyRegisterCompleteRequest request = new PasskeyRegisterCompleteRequest(
            "some-challenge",
            "irrelevant-credential-id",
            Base64.getUrlEncoder().encodeToString("garbage".getBytes()),
            Base64.getUrlEncoder().encodeToString("garbage".getBytes()));

        assertThatThrownBy(() -> service.completeRegistration(9L, request))
            .isInstanceOf(CustomException.class)
            .hasMessageContaining("does not belong");
    }

    @Test
    void completeRegistrationRejectsMalformedAttestation() {
        when(passkeyChallengeHelper.consumeChallenge("some-challenge")).thenReturn(9L);

        PasskeyRegisterCompleteRequest request = new PasskeyRegisterCompleteRequest(
            "some-challenge",
            "irrelevant-credential-id",
            Base64.getUrlEncoder().encodeToString("not-a-real-attestation-object".getBytes()),
            Base64.getUrlEncoder().encodeToString("not-a-real-client-data-json".getBytes()));

        assertThatThrownBy(() -> service.completeRegistration(9L, request))
            .isInstanceOf(CustomException.class);
    }

    /**
     * Fix 4: {@code Base64.getUrlDecoder().decode} throws {@link IllegalArgumentException}, which is
     * NOT one of the two exceptions the {@code webAuthnManager.validate} guard catches. Decoding
     * used to happen outside that guard, so this input escaped as an HTTP 500 with a full stack
     * trace logged at ERROR. It must be the same clean 400 as garbage-but-decodable input.
     */
    @Test
    void completeRegistrationRejectsMalformedBase64AsBadRequestNotServerError() {
        when(passkeyChallengeHelper.consumeChallenge("some-challenge")).thenReturn(9L);

        // "###" is not valid base64url in either field
        for (PasskeyRegisterCompleteRequest request : List.of(
            new PasskeyRegisterCompleteRequest("some-challenge", "cred", "###", "Z2FyYmFnZQ"),
            new PasskeyRegisterCompleteRequest("some-challenge", "cred", "Z2FyYmFnZQ", "###"))) {

            assertThatThrownBy(() -> service.completeRegistration(9L, request))
                .isInstanceOf(CustomException.class)
                .extracting(e -> ((CustomException) e).getStatus())
                .isEqualTo(400);
        }
    }
}
