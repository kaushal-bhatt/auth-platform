package com.authplatform.auth.service.impl;

import com.authplatform.auth.config.WebAuthnProperties;
import com.authplatform.auth.dto.PasskeyLoginCompleteRequest;
import com.authplatform.auth.dto.PasskeyLoginInitResponse;
import com.authplatform.auth.dto.TokenResponse;
import com.authplatform.auth.entity.PasskeyCredentialEntity;
import com.authplatform.auth.entity.UserEntity;
import com.authplatform.auth.exception.CustomException;
import com.authplatform.auth.repository.PasskeyCredentialRepository;
import com.authplatform.auth.repository.UserRepository;
import com.authplatform.auth.service.PasskeyLoginFlowService;
import com.authplatform.auth.service.TokenService;
import com.authplatform.auth.util.EmailNormalizer;
import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.converter.AttestedCredentialDataConverter;
import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.credential.CredentialRecord;
import com.webauthn4j.credential.CredentialRecordImpl;
import com.webauthn4j.data.AuthenticationData;
import com.webauthn4j.data.AuthenticationParameters;
import com.webauthn4j.data.AuthenticationRequest;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.statement.NoneAttestationStatement;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorOutputs;
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.validator.exception.ValidationException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Base64;
import java.util.List;

/**
 * Implements the WebAuthn authentication (login) ceremony's server side: issuing a challenge plus
 * the allowed credential id list for {@code navigator.credentials.get()}, then validating the
 * browser's assertion response and, on success, issuing the same token pair password login does.
 * <p>
 * Security notes (mirrors the Task 14 write-up in {@link PasskeyRegistrationServiceImpl} for the
 * concerns shared with registration):
 * <ul>
 *   <li><b>Challenge ownership.</b> {@link #completeLogin} consumes the challenge via
 *   {@link PasskeyChallengeHelper#consumeChallenge(String)} - single-use, see that class's javadoc
 *   - which returns the userId it was issued to. The stored credential looked up by
 *   {@code request.credentialId()} is then required to belong to that same userId
 *   ({@code .filter(credential -> credential.getUserId().equals(userId))}) before anything else
 *   happens. Without this check, a validly-signed assertion for user B's credential could be
 *   replayed against a challenge issued to user A.</li>
 *   <li><b>rpId/origin never come from the request.</b> Both are read exclusively from
 *   {@link WebAuthnProperties} (server configuration), never from
 *   {@code PasskeyLoginCompleteRequest}. The challenge embedded in {@link ServerProperty} is the
 *   server-issued value already proven above to be a real, unexpired challenge bound to this
 *   credential's owner - not anything the client could substitute.</li>
 *   <li><b>Sign-count anti-replay.</b> {@link #rejectIfSignCountRegressed} implements the
 *   WebAuthn-recommended check: if the authenticator's new signature counter is non-zero and did
 *   not strictly increase versus the stored value, that is a signal the authenticator may have
 *   been cloned, and the attempt is rejected. A signature counter of exactly {@code 0} is treated
 *   as "this authenticator does not implement a counter" (common for platform/passkey
 *   authenticators, e.g. those that sync across devices) - per the WebAuthn spec, a
 *   {@code 0} counter deliberately skips this check rather than being compared as a regression.
 *   The practical consequence is that such authenticators get <em>no</em> replay protection from
 *   the counter at all; that is an accepted, spec-conformant limitation of the sign-count
 *   mechanism itself; the challenge single-use guarantee is the countermeasure actually preventing
 *   replay of any individual assertion. The stored count is persisted only after this check
 *   passes.</li>
 *   <li><b>Two sibling exceptions from {@code WebAuthnManager#validate}.</b> It throws both
 *   {@link ValidationException} (well-formed input that fails a WebAuthn rule) and
 *   {@link DataConversionException} (input that is not even parseable CBOR/JSON) - two distinct,
 *   non-related unchecked exceptions. Both are client errors and both must map to the same 401,
 *   exactly as {@link PasskeyRegistrationServiceImpl#completeRegistration} already does for the
 *   registration ceremony; catching only the former would let malformed client input escape this
 *   method and fall through to {@code GlobalExceptionHandler}'s catch-all as a 500.</li>
 *   <li><b>Malformed base64url is a client error too.</b> Every request field is decoded through
 *   {@link #decode(String)}, which turns {@code Base64}'s {@link IllegalArgumentException} into the
 *   same clean 401 the two exceptions above produce. Decoding used to sit outside any guarded
 *   region, so a {@code signature} of {@code "###"} - reachable with no credentials at all, since
 *   {@code /passkey/login/init} is public and hands out a live challenge - escaped as a 500 plus a
 *   full stack trace at ERROR level, repeatable without limit. Valid base64 carrying garbage CBOR
 *   was already a clean 401, so invalid base64 producing a 500 was an inconsistency as well as a
 *   log-flooding vector. The offending value is never logged or echoed.</li>
 *   <li><b>Uniform failure responses on {@link #completeLogin}.</b> Every rejection after the
 *   challenge has been consumed returns the identical status and message
 *   ({@link #PASSKEY_AUTHENTICATION_FAILED}). This method used to return four textually distinct
 *   401s - including {@code "user no longer exists"}, which told an anonymous caller that an
 *   account had been deleted, and one embedding webauthn4j's own exception text, which reflected
 *   library internals straight back to the caller. Uniform messages here match how
 *   {@code LoginServiceImpl} and {@code TokenServiceImpl} already behave.</li>
 *   <li><b>User enumeration.</b> {@link #initLogin} is an unauthenticated, anonymous endpoint.
 *   Both failure branches - "no such user" and "user exists but has no passkeys registered" -
 *   throw the exact same status and message ({@link #INVALID_LOGIN_ATTEMPT}), mirroring
 *   {@code LoginServiceImpl}/{@code TokenServiceImpl}'s existing uniform-failure pattern, so a
 *   caller cannot use the response to learn whether an email is registered.</li>
 *   <li><b>Never log</b> the assertion, client data, signature, credential id, or the email - this
 *   class does not log at all, on the success or failure paths of either method, for that
 *   reason.</li>
 *   <li><b>No rate limiting.</b> Neither endpoint backing this service is rate limited, consistent
 *   with password login ({@code AuthController#login}); that is a pre-existing, cross-cutting gap
 *   this task does not introduce and is not in scope to fix here.</li>
 *   <li><b>Nested transaction guarantee.</b> {@link #completeLogin} is {@code @Transactional} and
 *   calls {@link PasskeyChallengeHelper#consumeChallenge(String)}, which runs its find-then-delete
 *   in its own {@code REQUIRES_NEW} transaction that commits independently. Task 14 already proves
 *   (see {@code PasskeyChallengeHelperOuterTransactionIntegrationTest}) that this means the
 *   challenge stays burned even if the outer transaction subsequently rolls back - e.g. because
 *   {@code webAuthnManager.validate} throws, the sign-count check rejects the attempt, or
 *   {@code tokenService.issueTokens} fails. {@code completeLogin} benefits from that exact same
 *   guarantee: a failed login attempt can never retry the same challenge, regardless of how far
 *   through this method the failure occurs.</li>
 * </ul>
 */
@Service
@RequiredArgsConstructor
public class PasskeyLoginFlowServiceImpl implements PasskeyLoginFlowService {

    private static final long TIMEOUT_MILLIS = 60_000;

    /**
     * The single message used for both "no such user" and "user has no passkeys registered".
     * Keeping them textually identical means an anonymous caller of {@link #initLogin} cannot use
     * the response to learn whether a given email is a registered account - see the class javadoc
     * "User enumeration" note.
     */
    private static final String INVALID_LOGIN_ATTEMPT = "invalid email or no passkeys registered";

    /**
     * The single message used for every {@link #completeLogin} rejection: unknown credential id, a
     * credential belonging to a different user than the challenge, malformed base64url, malformed
     * or invalid assertion bytes, a regressed sign count, and a user row that has since been
     * deleted. Keeping them textually identical means an anonymous caller cannot learn which of
     * those it hit - see the class javadoc "Uniform failure responses" note. Do not append the
     * specific cause to this message.
     */
    private static final String PASSKEY_AUTHENTICATION_FAILED = "passkey authentication failed";

    private final PasskeyChallengeHelper passkeyChallengeHelper;
    private final PasskeyCredentialRepository passkeyCredentialRepository;
    private final UserRepository userRepository;
    private final TokenService tokenService;
    private final WebAuthnProperties webAuthnProperties;
    private final WebAuthnManager webAuthnManager;
    private final AttestedCredentialDataConverter attestedCredentialDataConverter;

    @Override
    public PasskeyLoginInitResponse initLogin(String email) {
        // Normalise before lookup: Task 7 stores emails normalised (trimmed + lower-cased via
        // EmailNormalizer), so comparing the raw input here would make case/whitespace variants
        // of a registered email unable to log in. See EmailNormalizer's javadoc - every
        // user-by-email lookup in this project must go through it.
        String normalizedEmail = EmailNormalizer.normalize(email);

        UserEntity user = userRepository.findByEmail(normalizedEmail)
            .orElseThrow(() -> new CustomException(401, INVALID_LOGIN_ATTEMPT));

        List<PasskeyCredentialEntity> credentials = passkeyCredentialRepository.findByUserId(user.getId());
        if (credentials.isEmpty()) {
            throw new CustomException(401, INVALID_LOGIN_ATTEMPT);
        }

        Challenge challenge = passkeyChallengeHelper.issueChallenge(user.getId());
        List<String> credentialIds = credentials.stream().map(PasskeyCredentialEntity::getCredentialId).toList();

        return new PasskeyLoginInitResponse(
            Base64.getUrlEncoder().withoutPadding().encodeToString(challenge.getValue()),
            webAuthnProperties.getRelyingPartyId(),
            credentialIds,
            TIMEOUT_MILLIS
        );
    }

    @Override
    @Transactional
    public TokenResponse completeLogin(PasskeyLoginCompleteRequest request) {
        Long userId = passkeyChallengeHelper.consumeChallenge(request.challenge());

        // Challenge-ownership check: the credential must belong to the same user the challenge
        // was issued to, otherwise a validly-signed assertion for a different user's credential
        // could be replayed against this challenge. See class javadoc.
        PasskeyCredentialEntity storedCredential = passkeyCredentialRepository.findByCredentialId(request.credentialId())
            .filter(credential -> credential.getUserId().equals(userId))
            .orElseThrow(() -> new CustomException(401, PASSKEY_AUTHENTICATION_FAILED));

        AttestedCredentialData attestedCredentialData = attestedCredentialDataConverter.convert(
            Base64.getDecoder().decode(storedCredential.getAttestedCredentialData()));

        CredentialRecord credentialRecord = new CredentialRecordImpl(
            new NoneAttestationStatement(),
            null,
            null,
            null,
            storedCredential.getSignCount(),
            attestedCredentialData,
            new AuthenticationExtensionsAuthenticatorOutputs<RegistrationExtensionAuthenticatorOutput>(),
            null,
            null,
            null
        );

        AuthenticationRequest authenticationRequest = new AuthenticationRequest(
            decode(request.credentialId()),
            decode(request.authenticatorData()),
            decode(request.clientDataJSON()),
            decode(request.signature())
        );

        // origin and rpId come exclusively from server configuration (WebAuthnProperties), never
        // from the request body; the challenge is the server-issued one already proven above to
        // be bound to this credential's owner.
        ServerProperty serverProperty = new ServerProperty(
            Origin.create(webAuthnProperties.getOrigin()),
            webAuthnProperties.getRelyingPartyId(),
            new DefaultChallenge(request.challenge()),
            null
        );

        AuthenticationParameters authenticationParameters = new AuthenticationParameters(
            serverProperty, credentialRecord, null, true);

        AuthenticationData authenticationData;
        try {
            authenticationData = webAuthnManager.validate(authenticationRequest, authenticationParameters);
        } catch (ValidationException | DataConversionException e) {
            // WebAuthnManager#validate throws two distinct, sibling RuntimeExceptions for two
            // distinct failure modes: ValidationException when the input parses fine but fails a
            // WebAuthn validation rule (bad challenge, bad origin, bad signature, ...), and
            // DataConversionException when the bytes are not even well-formed CBOR/JSON to begin
            // with (e.g. a garbage authenticatorData/clientDataJSON). Both are client errors and
            // must map to the same 401, not just the former - a DataConversionException left
            // uncaught here would fall through to GlobalExceptionHandler's catch-all and surface
            // as an internal server error for what is plainly malformed input.
            //
            // e.getMessage() is deliberately NOT appended: it is webauthn4j's own text, it names
            // which WebAuthn rule failed (challenge vs origin vs signature), and it can quote the
            // caller's own bytes back at them. See the uniform-failure note in the class javadoc.
            throw new CustomException(401, PASSKEY_AUTHENTICATION_FAILED);
        }

        long newSignCount = authenticationData.getAuthenticatorData().getSignCount();
        rejectIfSignCountRegressed(newSignCount, storedCredential.getSignCount());
        storedCredential.setSignCount(newSignCount);
        passkeyCredentialRepository.save(storedCredential);

        UserEntity user = userRepository.findById(userId)
            .orElseThrow(() -> new CustomException(401, PASSKEY_AUTHENTICATION_FAILED));

        return tokenService.issueTokens(user.getId(), user.getEmail());
    }

    /**
     * Sign-count anti-replay check, factored out of {@link #completeLogin} so it can be unit
     * tested directly against the business rule, without having to drive a real cryptographic
     * assertion through {@code WebAuthnManager#validate} just to reach this branch - see
     * {@code PasskeyLoginFlowServiceImplTest} and the Task 15 report for why that would be fragile
     * busywork better left to webauthn4j's own test suite.
     * <p>
     * Package-private rather than private for that same reason - the test class in this package
     * calls it directly.
     *
     * @param newSignCount    the signature counter reported by this assertion
     * @param storedSignCount the signature counter on file for this credential
     */
    void rejectIfSignCountRegressed(long newSignCount, long storedSignCount) {
        if (newSignCount != 0 && newSignCount <= storedSignCount) {
            throw new CustomException(401, PASSKEY_AUTHENTICATION_FAILED);
        }
    }

    /**
     * Decodes one base64url request field, mapping malformed input to the same clean 401 every
     * other {@link #completeLogin} rejection uses.
     * <p>
     * {@code Base64.getUrlDecoder().decode} throws {@link IllegalArgumentException}, which is not
     * caught by the {@code ValidationException | DataConversionException} guard around
     * {@code webAuthnManager.validate}. Left unguarded it reached
     * {@code GlobalExceptionHandler}'s catch-all: HTTP 500 plus a full stack trace logged at ERROR.
     * That is unauthenticated-reachable (see the class javadoc), so it doubled as an ERROR-log
     * flooding vector.
     * <p>
     * Neither the offending value nor the decoder's exception message is logged or returned - the
     * value is attacker-supplied and the message quotes it.
     */
    private byte[] decode(String base64UrlValue) {
        try {
            return Base64.getUrlDecoder().decode(base64UrlValue);
        } catch (IllegalArgumentException e) {
            throw new CustomException(401, PASSKEY_AUTHENTICATION_FAILED);
        }
    }
}
