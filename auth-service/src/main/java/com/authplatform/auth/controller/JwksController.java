package com.authplatform.auth.controller;

import com.authplatform.auth.service.KeysService;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Publishes the RFC 7517 JWKS document that {@code auth-jwt-lib}'s {@code JwksClient} (and any
 * other verifier) fetches to resolve a token's signing key by {@code kid}. Deliberately left
 * unannotated with {@code @JwtTokenVerification}: this endpoint must be reachable anonymously -
 * a verifier that itself needs a bearer token to fetch the keys used to verify bearer tokens is
 * a bootstrapping deadlock.
 * <p>
 * Publishes every stored key ({@link KeysService#getAllPublicJwks()}), not just the active one:
 * a JWKS is a key <em>set</em> by definition, and two problems require the full set rather than
 * a single key -
 * <ol>
 *   <li>Multi-instance deployments: {@code KeysService.getActiveKey()} is only
 *       JVM-{@code synchronized}, so two instances starting against an empty database can each
 *       persist their own key. Publishing only "the" active key picked arbitrarily by whichever
 *       instance serves a given request would make tokens signed by the other instance's key
 *       unverifiable.</li>
 *   <li>Key rotation: a token signed by a key that was just rotated out must still verify until
 *       it expires. Publishing only the current key would invalidate every outstanding token the
 *       moment a new one is generated.</li>
 * </ol>
 * Every {@link RSAKey} returned by {@link KeysService#getAllPublicJwks()} is already built from
 * an {@code RSAPublicKey} only (see {@code KeysServiceImpl#toPublicJwk}) - the private exponent
 * and CRT parameters are never read into it in the first place, so there is no private material
 * for {@link JWKSet#toJSONObject()} to filter out even though it does so anyway.
 */
@RestController
@RequiredArgsConstructor
public class JwksController {

    private final KeysService keysService;

    @GetMapping("/.well-known/jwks.json")
    public Map<String, Object> jwks() {
        List<RSAKey> publicJwks = keysService.getAllPublicJwks();
        List<JWK> jwks = new ArrayList<>(publicJwks);
        return new JWKSet(jwks).toJSONObject();
    }
}
