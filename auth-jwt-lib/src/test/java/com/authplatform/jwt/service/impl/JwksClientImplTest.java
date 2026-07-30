package com.authplatform.jwt.service.impl;

import com.authplatform.jwt.config.JwtLibProperties;
import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

class JwksClientImplTest {

    private HttpServer server;
    private JwksClientImpl jwksClient;
    private JwtLibProperties properties;
    private String keyId;
    private AtomicInteger requestCount;
    private volatile String jwksJson;

    @BeforeEach
    void setUp() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();
        keyId = "test-key-1";

        RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
            .privateKey((RSAPrivateKey) keyPair.getPrivate())
            .keyID(keyId)
            .keyUse(KeyUse.SIGNATURE)
            .build()
            .toPublicJWK();
        jwksJson = new JWKSet(rsaKey).toString();

        requestCount = new AtomicInteger(0);
        server = HttpServer.create(new InetSocketAddress(0), 0);
        server.createContext("/.well-known/jwks.json", exchange -> {
            requestCount.incrementAndGet();
            byte[] bytes = jwksJson.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
        });
        server.start();

        properties = new JwtLibProperties();
        properties.setJwksUri("http://localhost:" + server.getAddress().getPort() + "/.well-known/jwks.json");
        properties.setExpectedIssuer("auth-service");
        jwksClient = new JwksClientImpl(properties);
    }

    @AfterEach
    void tearDown() {
        server.stop(0);
    }

    @Test
    void getKeyFetchesAndCachesFromJwksEndpoint() {
        Optional<RSAKey> firstCall = jwksClient.getKey(keyId);
        Optional<RSAKey> secondCall = jwksClient.getKey(keyId);

        assertThat(firstCall).isPresent();
        assertThat(firstCall.get().getKeyID()).isEqualTo(keyId);
        assertThat(secondCall).isPresent();
        assertThat(secondCall.get().getKeyID()).isEqualTo(keyId);
        assertThat(requestCount.get()).isEqualTo(1);
    }

    @Test
    void getKeyReturnsEmptyForUnknownKeyId() {
        Optional<RSAKey> result = jwksClient.getKey("unknown-key-id");

        assertThat(result).isEmpty();
    }

    @Test
    void getKeyThrottlesRepeatedRefreshesForUnknownKeyIdWithinThrottleWindow() {
        Optional<RSAKey> first = jwksClient.getKey("unknown-key-id");
        Optional<RSAKey> second = jwksClient.getKey("unknown-key-id");
        Optional<RSAKey> third = jwksClient.getKey("unknown-key-id");

        assertThat(first).isEmpty();
        assertThat(second).isEmpty();
        assertThat(third).isEmpty();
        assertThat(requestCount.get()).isEqualTo(1);
    }

    @Test
    void explicitRefreshAlwaysFetchesEvenImmediatelyAfterAnotherRefresh() {
        jwksClient.refresh();
        jwksClient.refresh();

        assertThat(requestCount.get()).isEqualTo(2);
    }

    @Test
    void getKeyRefetchesUnknownKeyIdAfterThrottleWindowElapses() {
        properties.setMinRefreshIntervalSeconds(0);

        Optional<RSAKey> first = jwksClient.getKey("unknown-key-id");
        Optional<RSAKey> second = jwksClient.getKey("unknown-key-id");

        assertThat(first).isEmpty();
        assertThat(second).isEmpty();
        assertThat(requestCount.get()).isEqualTo(2);
    }

    @Test
    void getKeyRejectsEncryptionOnlyKey() throws Exception {
        jwksJson = new JWKSet(publishedKey(2048, KeyUse.ENCRYPTION, null)).toString();

        Optional<RSAKey> result = jwksClient.getKey(keyId);

        assertThat(result).isEmpty();
    }

    @Test
    void getKeyRejectsKeyDeclaringANonRsaSignatureAlgorithm() throws Exception {
        jwksJson = new JWKSet(publishedKey(2048, KeyUse.SIGNATURE, JWEAlgorithm.RSA_OAEP_256)).toString();

        Optional<RSAKey> result = jwksClient.getKey(keyId);

        assertThat(result).isEmpty();
    }

    @Test
    void getKeyRejectsUndersizedRsaKey() throws Exception {
        jwksJson = new JWKSet(publishedKey(1024, KeyUse.SIGNATURE, null)).toString();

        Optional<RSAKey> result = jwksClient.getKey(keyId);

        assertThat(result).isEmpty();
    }

    @Test
    void getKeyAcceptsKeyDeclaringRs256AndNoUse() throws Exception {
        jwksJson = new JWKSet(publishedKey(2048, null, JWSAlgorithm.RS256)).toString();

        Optional<RSAKey> result = jwksClient.getKey(keyId);

        assertThat(result).isPresent();
        assertThat(result.get().getKeyID()).isEqualTo(keyId);
    }

    @Test
    void getKeyAcceptsKeyWithBothUseAndAlgorithmAbsent() throws Exception {
        // rfc 7517 makes both "use" and "alg" optional; a key that declares neither must still
        // be trusted for signature verification. this is the exact case none of the other
        // fixtures cover: getKeyAcceptsKeyDeclaringRs256AndNoUse always sets alg=RS256.
        jwksJson = new JWKSet(publishedKey(2048, null, null)).toString();

        Optional<RSAKey> result = jwksClient.getKey(keyId);

        assertThat(result).isPresent();
        assertThat(result.get().getKeyID()).isEqualTo(keyId);
    }

    @Test
    void getKeyResolvesKeyIdLongerThan64CharactersUsingTheUnsanitizedValue() throws Exception {
        // the message-truncation limit in JwtVerificationServiceImpl is 64 characters, but that
        // truncation must apply only to failure messages, never to the actual jwks lookup key.
        // mockito-based tests of the verification service cannot prove this (Optional.empty() is
        // returned for any unmatched argument, so a wrongly-truncated lookup would still pass);
        // this test exercises the real JwksClientImpl end to end with a long, legitimate kid.
        String longKeyId = "a-legitimate-key-id-that-happens-to-be-longer-than-sixty-four-characters-long";
        assertThat(longKeyId.length()).isGreaterThan(64);

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();
        RSAKey longKidKey = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
            .keyID(longKeyId)
            .keyUse(KeyUse.SIGNATURE)
            .build();
        jwksJson = new JWKSet(longKidKey).toString();

        Optional<RSAKey> result = jwksClient.getKey(longKeyId);

        assertThat(result).isPresent();
        assertThat(result.get().getKeyID()).isEqualTo(longKeyId);
    }

    private RSAKey publishedKey(int keySize, KeyUse keyUse, Algorithm algorithm) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(keySize);
        KeyPair keyPair = generator.generateKeyPair();
        return new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
            .keyID(keyId)
            .keyUse(keyUse)
            .algorithm(algorithm)
            .build();
    }
}
