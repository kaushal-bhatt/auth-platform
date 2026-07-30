package com.authplatform.jwt.service.impl;

import com.authplatform.jwt.config.JwtLibProperties;
import com.authplatform.jwt.service.JwksClient;
import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.web.client.RestClient;

import java.text.ParseException;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

@Slf4j
public class JwksClientImpl implements JwksClient {

    private static final long NO_REFRESH_ATTEMPTED_YET = Long.MIN_VALUE;

    /**
     * smallest rsa modulus accepted for signature verification. anything below this is
     * considered too weak to trust regardless of what the jwks endpoint published.
     */
    private static final int MIN_RSA_MODULUS_BITS = 2048;

    private final JwtLibProperties properties;
    private final RestClient restClient;
    private volatile JWKSet cachedJwkSet;
    private final AtomicLong lastRefreshAttemptNanos = new AtomicLong(NO_REFRESH_ATTEMPTED_YET);

    public JwksClientImpl(JwtLibProperties properties) {
        this.properties = properties;
        SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
        requestFactory.setConnectTimeout(properties.getConnectTimeoutMillis());
        requestFactory.setReadTimeout(properties.getReadTimeoutMillis());
        this.restClient = RestClient.builder()
            .requestFactory(requestFactory)
            .build();
    }

    @Override
    public Optional<RSAKey> getKey(String keyId) {
        RSAKey cachedKey = findKey(cachedJwkSet, keyId);
        if (cachedKey != null) {
            return Optional.of(cachedKey);
        }
        if (!throttleWindowElapsed()) {
            log.debug("skipping automatic jwks refresh for keyId: {}, throttle window not elapsed", keyId);
            return Optional.empty();
        }
        synchronized (this) {
            // another thread may have already fetched the key while we waited for the lock
            RSAKey recheckedKey = findKey(cachedJwkSet, keyId);
            if (recheckedKey != null) {
                return Optional.of(recheckedKey);
            }
            // another thread may have already performed the throttled refresh; don't fetch again
            if (throttleWindowElapsed()) {
                doRefresh();
            }
        }
        return Optional.ofNullable(findKey(cachedJwkSet, keyId));
    }

    @Override
    public void refresh() {
        synchronized (this) {
            doRefresh();
        }
    }

    private void doRefresh() {
        try {
            String json = restClient.get()
                .uri(properties.getJwksUri())
                .retrieve()
                .body(String.class);
            assert json != null;
            this.cachedJwkSet = filterUsableKeys(JWKSet.parse(json));
            log.debug("refreshed jwks from {}", properties.getJwksUri());
        } catch (ParseException e) {
            throw new IllegalStateException("failed to parse jwks response from " + properties.getJwksUri(), e);
        } finally {
            lastRefreshAttemptNanos.set(System.nanoTime());
        }
    }

    /**
     * keeps only the keys that are usable for signature verification, discarding the rest right
     * here at refresh time so the cache never holds a key that {@link #findKey} would otherwise
     * have to reject. this is what lets the per-lookup path stay silent: an attacker who reads a
     * non-signature or undersized key id straight out of the public jwks and replays it in a
     * token header can no longer trigger a log line per request, since the rejection already
     * happened once, here, and is logged once, here.
     */
    private static JWKSet filterUsableKeys(JWKSet jwkSet) {
        List<JWK> allKeys = jwkSet.getKeys();
        List<JWK> usableKeys = allKeys.stream()
            .filter(jwk -> jwk instanceof RSAKey rsaKey && usableForSignatureVerification(rsaKey))
            .collect(Collectors.toList());
        int skipped = allKeys.size() - usableKeys.size();
        if (skipped > 0) {
            log.warn("jwks refresh: skipped {} of {} published keys that are not usable for signature "
                    + "verification (wrong declared use, non-rsa signature algorithm, or rsa modulus "
                    + "below {} bits)",
                skipped, allKeys.size(), MIN_RSA_MODULUS_BITS);
        } else {
            log.debug("jwks refresh: all {} published keys are usable for signature verification",
                allKeys.size());
        }
        return new JWKSet(usableKeys);
    }

    private boolean throttleWindowElapsed() {
        long lastAttempt = lastRefreshAttemptNanos.get();
        if (lastAttempt == NO_REFRESH_ATTEMPTED_YET) {
            return true;
        }
        long elapsedSeconds = (System.nanoTime() - lastAttempt) / 1_000_000_000L;
        return elapsedSeconds >= properties.getMinRefreshIntervalSeconds();
    }

    /**
     * pure, silent lookup with no side effects: the cache built by {@link #filterUsableKeys}
     * already contains only keys that are usable for signature verification, so this path must
     * not log anything - doing so per lookup is exactly the unauthenticated log flood this class
     * is required to avoid.
     */
    private static RSAKey findKey(JWKSet jwkSet, String keyId) {
        if (jwkSet == null) {
            return null;
        }
        JWK jwk = jwkSet.getKeyByKeyId(keyId);
        return jwk instanceof RSAKey rsaKey ? rsaKey : null;
    }

    /**
     * a key published in the jwks is only trusted for signature verification when it does not
     * declare itself to be for something else, and when it is strong enough. a key that
     * declares no {@code use} or no {@code alg} is accepted on those two counts, since both
     * members are optional in rfc 7517 and a key without them is usable for signing.
     */
    private static boolean usableForSignatureVerification(RSAKey rsaKey) {
        KeyUse keyUse = rsaKey.getKeyUse();
        if (keyUse != null && !KeyUse.SIGNATURE.equals(keyUse)) {
            return false;
        }
        Algorithm algorithm = rsaKey.getAlgorithm();
        if (algorithm != null && !JWSAlgorithm.Family.RSA.contains(JWSAlgorithm.parse(algorithm.getName()))) {
            return false;
        }
        return rsaKey.size() >= MIN_RSA_MODULUS_BITS;
    }
}
