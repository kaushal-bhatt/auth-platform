package com.authplatform.jwt.service;

import com.authplatform.jwt.model.JwtClaims;
import com.authplatform.jwt.model.JwtVerificationResult;

public interface JwtVerificationService {

    /**
     * Fully verifies the supplied JWT: the header algorithm, the signature against the
     * published JWKS key, and every claim validation. This is the only method on this
     * interface whose outcome may be used to make an authentication or authorization
     * decision.
     * <p>
     * This method never throws. Every failure mode - a malformed token, an unknown or
     * missing key id, a bad signature, an invalid claim, a JWKS outage, or an unexpected
     * internal error - is reported as a failed {@link JwtVerificationResult} carrying a
     * human readable reason, never as an exception.
     *
     * @param token the compact serialised JWT; may be {@code null} or blank, in which case
     *              a failure result is returned
     * @return a successful result carrying the verified claims, or a failure result
     *         carrying the reason; never {@code null}
     */
    JwtVerificationResult verify(String token);

    /**
     * Decodes the claims of the supplied JWT <strong>without verifying its signature</strong>.
     * <p>
     * <strong>DANGER - this method performs no verification whatsoever.</strong> The returned
     * {@link JwtClaims}, including {@code userId}, come straight from a payload that has not
     * been authenticated in any way. Anybody can mint a token with arbitrary claims, sign it
     * with a key of their own choosing (or not sign it meaningfully at all), and this method
     * will decode it happily. Therefore it MUST NEVER be used to make an authentication or
     * authorization decision, to identify the caller, or to populate a security context.
     * Use {@link #verify(String)} for all of that.
     * <p>
     * The only legitimate uses are non-security concerns such as logging, metrics tagging,
     * or inspecting the issuer in order to decide which verifier to route a token to.
     *
     * @param token the compact serialised JWT; must not be {@code null} or blank
     * @return the decoded, <em>unverified</em> claims
     * @throws IllegalArgumentException if the token is {@code null}, blank, malformed, or its
     *                                  claims cannot be decoded
     */
    JwtClaims extractClaimsWithoutVerification(String token);
}
