package com.authplatform.auth.config;

import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.converter.AttestedCredentialDataConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Shared webauthn4j beans consumed by both the registration ceremony (Task 14) and the
 * authentication ceremony (Task 15).
 * <p>
 * {@link WebAuthnManager#createNonStrictWebAuthnManager()} is a deliberate, recorded choice, not
 * an oversight: "non-strict" means it does not verify attestation certificate chains and accepts
 * self-attestation / "none" attestation. For a passkey-style deployment - where the relying party
 * cares that a FIDO2 authenticator produced the credential, not which vendor manufactured it -
 * that is the normal and correct configuration. See the Task 14 report for the full rationale.
 */
@Configuration
public class WebAuthnConfig {

    @Bean
    public WebAuthnManager webAuthnManager() {
        return WebAuthnManager.createNonStrictWebAuthnManager();
    }

    @Bean
    public AttestedCredentialDataConverter attestedCredentialDataConverter() {
        return new AttestedCredentialDataConverter(new ObjectConverter());
    }
}
