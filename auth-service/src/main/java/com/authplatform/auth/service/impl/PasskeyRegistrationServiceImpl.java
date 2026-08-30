package com.authplatform.auth.service.impl;

import com.authplatform.auth.config.WebAuthnProperties;
import com.authplatform.auth.dto.PasskeyRegisterCompleteRequest;
import com.authplatform.auth.dto.PasskeyRegisterInitResponse;
import com.authplatform.auth.entity.PasskeyCredentialEntity;
import com.authplatform.auth.entity.UserEntity;
import com.authplatform.auth.exception.CustomException;
import com.authplatform.auth.repository.PasskeyCredentialRepository;
import com.authplatform.auth.repository.UserRepository;
import com.authplatform.auth.service.PasskeyRegistrationService;
import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.converter.AttestedCredentialDataConverter;
import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.data.PublicKeyCredentialParameters;
import com.webauthn4j.data.PublicKeyCredentialType;
import com.webauthn4j.data.RegistrationData;
import com.webauthn4j.data.RegistrationParameters;
import com.webauthn4j.data.RegistrationRequest;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.validator.exception.ValidationException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Base64;
import java.util.List;

/**
 * Implements the WebAuthn registration ceremony's server side: issuing a challenge plus relying
 * party/user info for {@code navigator.credentials.create()}, then validating the browser's
 * attestation response and persisting the resulting credential.
 * <p>
 * Security notes (see the Task 14 report for the full write-up):
 * <ul>
 *   <li><b>Challenge ownership.</b> {@link #completeRegistration} consumes the challenge via
 *   {@link PasskeyChallengeHelper#consumeChallenge(String)} - which is single-use, see that
 *   class's javadoc - and then checks the userId it was issued to against the authenticated
 *   caller passed in by the controller. Without this check, user A could complete registration
 *   against a challenge issued to user B (e.g. leaked/guessed), attaching A's attestation to B's
 *   account.</li>
 *   <li><b>rpId/origin never come from the request.</b> Both are read exclusively from
 *   {@link WebAuthnProperties}, which is server configuration - never from
 *   {@code PasskeyRegisterCompleteRequest}. The challenge embedded in {@link ServerProperty} is
 *   likewise the server-issued value ({@code request.challenge()}, the same string that was just
 *   proven to belong to this user), not anything else the client could substitute.</li>
 *   <li><b>Attestation trust.</b> The injected {@link WebAuthnManager} is built via
 *   {@code createNonStrictWebAuthnManager()} (see {@code WebAuthnConfig}), which does not verify
 *   attestation certificate chains and accepts self-attestation/"none" attestation. That is the
 *   normal, correct choice for a passkey-style deployment and is a recorded decision, not an
 *   oversight.</li>
 *   <li><b>Malformed base64url is a client error.</b> Every request field is decoded through
 *   {@link #decode(String)}, which turns {@code Base64}'s {@link IllegalArgumentException} into the
 *   same clean 400 a malformed-but-decodable attestation already produces. Decoding used to sit
 *   outside the {@code ValidationException | DataConversionException} guard, so an
 *   {@code attestationObject} of {@code "###"} escaped as a 500 plus a full stack trace at ERROR
 *   level. The offending value is never logged or echoed.</li>
 *   <li><b>Never log</b> the attestation object, client data, credential id, or the user's email -
 *   this class does not log at all on the success or failure paths of {@code completeRegistration}
 *   for that reason.</li>
 * </ul>
 */
@Service
@RequiredArgsConstructor
public class PasskeyRegistrationServiceImpl implements PasskeyRegistrationService {

    private static final long TIMEOUT_MILLIS = 60_000;

    /**
     * Signature algorithms this service will register a credential for.
     * <p>
     * One list, used twice: it is what {@link #initRegistration} advertises to the browser, and
     * what {@link #completeRegistration} validates the result against. Those were separate before
     * — the browser was offered ES256 only, while validation passed {@code null} for the
     * parameters, meaning webauthn4j accepted <em>any</em> algorithm. A server should not accept
     * something it never offered, and keeping the two in one place is the only way that stays
     * true.
     * <p>
     * <strong>ES256 only was also a compatibility problem.</strong> Chrome warns about it
     * directly: an authenticator that supports RS256 but not ES256 — some TPM-backed Windows
     * Hello configurations, some older security keys — simply cannot register. ES256 stays first
     * because authenticators pick the first algorithm they support and it is the smaller, more
     * modern choice; RS256 is the fallback that makes the rest of the field work.
     */
    private static final List<PublicKeyCredentialParameters> SUPPORTED_ALGORITHMS = List.of(
        new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256),
        new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.RS256)
    );

    private final PasskeyChallengeHelper passkeyChallengeHelper;
    private final PasskeyCredentialRepository passkeyCredentialRepository;
    private final UserRepository userRepository;
    private final WebAuthnProperties webAuthnProperties;
    private final WebAuthnManager webAuthnManager;
    private final AttestedCredentialDataConverter attestedCredentialDataConverter;

    @Override
    public PasskeyRegisterInitResponse initRegistration(Long userId) {
        UserEntity user = userRepository.findById(userId)
            .orElseThrow(() -> new CustomException(404, "user not found"));

        Challenge challenge = passkeyChallengeHelper.issueChallenge(userId);

        return new PasskeyRegisterInitResponse(
            Base64.getUrlEncoder().withoutPadding().encodeToString(challenge.getValue()),
            user.getId().toString(),
            user.getEmail(),
            webAuthnProperties.getRelyingPartyId(),
            webAuthnProperties.getRelyingPartyName(),
            SUPPORTED_ALGORITHMS.stream()
                .map(p -> new PasskeyRegisterInitResponse.PubKeyCredParam(
                    p.getType().getValue(), (int) p.getAlg().getValue()))
                .toList(),
            TIMEOUT_MILLIS
        );
    }

    @Override
    @Transactional
    public void completeRegistration(Long userId, PasskeyRegisterCompleteRequest request) {
        Long challengeUserId = passkeyChallengeHelper.consumeChallenge(request.challenge());
        if (!challengeUserId.equals(userId)) {
            throw new CustomException(400, "passkey challenge does not belong to this user");
        }

        RegistrationRequest registrationRequest = new RegistrationRequest(
            decode(request.attestationObject()),
            decode(request.clientDataJSON())
        );

        // origin and rpId come exclusively from server configuration (WebAuthnProperties), never
        // from the request body; the challenge is the server-issued one already proven above to
        // belong to this user.
        ServerProperty serverProperty = new ServerProperty(
            Origin.create(webAuthnProperties.getOrigin()),
            webAuthnProperties.getRelyingPartyId(),
            new DefaultChallenge(request.challenge()),
            null
        );

        // The algorithm list is passed, not null: webauthn4j then refuses a credential signed
        // with anything this service did not advertise. With null it accepted whatever arrived.
        RegistrationParameters registrationParameters =
            new RegistrationParameters(serverProperty, SUPPORTED_ALGORITHMS, true);

        RegistrationData registrationData;
        try {
            registrationData = webAuthnManager.validate(registrationRequest, registrationParameters);
        } catch (ValidationException | DataConversionException e) {
            // WebAuthnManager#validate throws two distinct, sibling RuntimeExceptions for two
            // distinct failure modes: ValidationException when the input parses fine but fails a
            // WebAuthn validation rule (bad challenge, bad origin, bad signature, ...), and
            // DataConversionException when the bytes are not even well-formed CBOR/JSON to begin
            // with (e.g. a garbage attestationObject/clientDataJSON). Both are client errors and
            // must map to the same 400, not just the former - a DataConversionException left
            // uncaught here would fall through to GlobalExceptionHandler's catch-all and surface
            // as an internal server error for what is plainly malformed input.
            throw new CustomException(400, "passkey registration failed validation: " + e.getMessage());
        }

        AttestedCredentialData attestedCredentialData = registrationData.getAttestationObject()
            .getAuthenticatorData()
            .getAttestedCredentialData();
        if (attestedCredentialData == null) {
            throw new CustomException(400, "attestation did not include credential data");
        }

        String credentialId = Base64.getUrlEncoder().withoutPadding()
            .encodeToString(attestedCredentialData.getCredentialId());
        // Check-then-insert race: two concurrent registrations of the same credential id could
        // both pass this check before either save() commits. That is acceptable here - the
        // unique constraint on passkey_credential.credential_id is the real guard, and
        // GlobalExceptionHandler already maps the resulting DataIntegrityViolationException to
        // 409, so the outcome is correct either way. This mirrors already-accepted check-then-act
        // patterns elsewhere in this project; no additional locking is added.
        if (passkeyCredentialRepository.findByCredentialId(credentialId).isPresent()) {
            throw new CustomException(409, "this passkey is already registered");
        }

        long signCount = registrationData.getAttestationObject().getAuthenticatorData().getSignCount();

        PasskeyCredentialEntity entity = PasskeyCredentialEntity.builder()
            .userId(userId)
            .credentialId(credentialId)
            .attestedCredentialData(Base64.getEncoder()
                .encodeToString(attestedCredentialDataConverter.convert(attestedCredentialData)))
            .signCount(signCount)
            .createdAt(Instant.now())
            .build();
        passkeyCredentialRepository.save(entity);
    }

    /**
     * Decodes one base64url request field, mapping malformed input to the same clean 400 a
     * malformed-but-decodable attestation already produces.
     * <p>
     * {@code Base64.getUrlDecoder().decode} throws {@link IllegalArgumentException}, which is not
     * caught by the {@code ValidationException | DataConversionException} guard around
     * {@code webAuthnManager.validate}. Left unguarded it reached
     * {@code GlobalExceptionHandler}'s catch-all: HTTP 500 plus a full stack trace logged at ERROR,
     * for what is plainly malformed client input - and inconsistent with valid base64 carrying
     * garbage CBOR, which was already a clean 400.
     * <p>
     * Neither the offending value nor the decoder's exception message is logged or returned - the
     * value is caller-supplied and the message quotes it.
     */
    private byte[] decode(String base64UrlValue) {
        try {
            return Base64.getUrlDecoder().decode(base64UrlValue);
        } catch (IllegalArgumentException e) {
            throw new CustomException(400, "passkey registration failed validation");
        }
    }
}
