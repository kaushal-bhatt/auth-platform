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
import java.util.Date;
import java.util.UUID;

@Component
@RequiredArgsConstructor
public class JwtIssuer {

    private final KeysService keysService;
    private final JwtIssuerProperties issuerProperties;

    public String issueAccessToken(Long userId, String email, UUID sessionId) {
        CertificateEntity certificate = keysService.getActiveKey();
        Instant now = Instant.now();
        Instant expiry = now.plus(issuerProperties.getAccessTokenExpiryMinutes(), ChronoUnit.MINUTES);

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
            .subject(userId.toString())
            .claim("email", email)
            .claim("sess", sessionId.toString())
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
