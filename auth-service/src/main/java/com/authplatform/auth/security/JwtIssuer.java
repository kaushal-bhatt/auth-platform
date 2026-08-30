package com.authplatform.auth.security;

import com.authplatform.auth.config.JwtIssuerProperties;
import com.authplatform.auth.entity.CertificateEntity;
import com.authplatform.auth.service.KeysService;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.UUID;

@Component
@RequiredArgsConstructor
public class JwtIssuer {

    private final KeysService keysService;
    private final JwtIssuerProperties issuerProperties;

    /**
     * @param roles the user's granted roles, possibly empty — never null. Emitted as a
     *              {@code roles} claim so a relying party can decide what a token is allowed to
     *              do, not merely that it is valid. This matters because registration is open on
     *              the public demo: without it, "holds a signature-valid token" means "signed up",
     *              which is not a basis for letting anyone into anything.
     *              <p>
     *              Always present, even when empty, so consumers can read one shape rather than
     *              handling a missing claim as a separate case.
     *              <p>
     *              Note that auth-jwt-lib's {@code JwtClaims} does not surface this yet — its
     *              consumers are Java services that have no use for it today, and widening that
     *              record is a breaking change for every caller. The relying party this was built
     *              for reads the claim straight off the verified token.
     */
    public String issueAccessToken(Long userId, String email, UUID sessionId, Collection<String> roles) {
        CertificateEntity certificate = keysService.getActiveKey();
        Instant now = Instant.now();
        Instant expiry = now.plus(issuerProperties.getAccessTokenExpiryMinutes(), ChronoUnit.MINUTES);

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
            .subject(userId.toString())
            .claim("email", email)
            .claim("sess", sessionId.toString())
            .claim("roles", List.copyOf(roles))
            // configuration-driven, not a literal: auth-jwt-lib's expected-audience check is
            // optional and currently unset, so nothing today would notice a mismatch. See
            // JwtIssuerProperties#audience.
            .audience(issuerProperties.getAudience())
            .issuer(issuerProperties.getIssuer())
            .issueTime(Date.from(now))
            .expirationTime(Date.from(expiry))
            .build();

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
            .keyID(certificate.getKeyId())
            .build();

        try {
            SignedJWT signedJWT = new SignedJWT(header, claims);
            signedJWT.sign(new RSASSASigner(keysService.toPrivateKey(certificate)));
            return signedJWT.serialize();
        } catch (JOSEException e) {
            throw new IllegalStateException("failed to sign jwt for user " + userId, e);
        }
    }

    public long accessTokenExpirySeconds() {
        return issuerProperties.getAccessTokenExpiryMinutes() * 60L;
    }
}
