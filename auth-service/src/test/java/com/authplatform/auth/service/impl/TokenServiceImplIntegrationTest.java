package com.authplatform.auth.service.impl;

import com.authplatform.auth.dto.TokenResponse;
import com.authplatform.auth.entity.TokenEntity;
import com.authplatform.auth.entity.UserEntity;
import com.authplatform.auth.exception.CustomException;
import com.authplatform.auth.repository.TokenRepository;
import com.authplatform.auth.repository.UserRepository;
import com.authplatform.auth.service.TokenService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Integration coverage for refresh-token rotation against a real PostgreSQL, because the invariant
 * being protected — a refresh token is redeemable <em>exactly once</em> — lives in the database's
 * locking and visibility rules and cannot be demonstrated with a mocked repository.
 * <p>
 * The defect this class pins: {@code refresh(...)} is a read-then-write. Hibernate emits
 * {@code SELECT ... WHERE refresh_token_hash=? AND revoked=false} followed by
 * {@code UPDATE token SET revoked=true WHERE id=?}. The UPDATE predicate is the primary key alone
 * — it does not re-check {@code revoked=false} — and {@code TokenEntity} has no {@code @Version}.
 * Under PostgreSQL's default READ COMMITTED isolation two transactions could therefore both SELECT
 * the row, both see {@code revoked=false}, and both UPDATE successfully (the second simply blocks,
 * then re-matches on {@code id}), minting two token pairs from one refresh token: two independent,
 * indefinitely renewable session chains. An attacker holding a stolen refresh token only had to
 * fire his request concurrently with the victim's for both to keep a live session.
 * <p>
 * The fix is the {@code PESSIMISTIC_WRITE} lock on
 * {@link TokenRepository#findByRefreshTokenHashAndRevokedFalse}, which makes the SELECT take a row
 * lock ({@code ... for no key update} as Hibernate's PostgreSQL dialect renders a write lock).
 * <p>
 * Both Fix-1 tests below were confirmed against a negative control: with the {@code @Lock}
 * annotation removed they fail 5 runs out of 5, the concurrency test reporting
 * {@code [REDEEMED, REDEEMED]}.
 */
@Testcontainers
@SpringBootTest
class TokenServiceImplIntegrationTest {

    private static final long LOCK_WAIT_PROOF_SECONDS = 2;
    private static final long GENEROUS_TIMEOUT_SECONDS = 60;

    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:16-alpine");

    @DynamicPropertySource
    static void configureDatasource(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
    }

    /**
     * Deliberately the interface, so every call goes through the Spring transactional proxy. A
     * pessimistic lock only has effect inside a transaction, so calling the impl directly would
     * silently test nothing.
     */
    @Autowired
    private TokenService tokenService;

    @Autowired
    private TokenRepository tokenRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PlatformTransactionManager transactionManager;

    private ExecutorService executor;

    /**
     * An explicit two-thread pool rather than {@code ForkJoinPool.commonPool()}: the common pool's
     * parallelism is {@code availableProcessors - 1} and can be 1, in which case a task that blocks
     * on a row lock would starve the second task and the lock-contention tests would deadlock
     * instead of failing meaningfully.
     */
    private ExecutorService executor() {
        if (executor == null) {
            executor = Executors.newFixedThreadPool(2);
        }
        return executor;
    }

    @AfterEach
    void shutdownExecutor() {
        if (executor != null) {
            executor.shutdownNow();
            executor = null;
        }
    }

    /**
     * THE critical test. Two simultaneous redemptions of the same refresh token must yield exactly
     * one success and one rejection.
     * <p>
     * Both threads park on a {@link CountDownLatch} and are released together to maximise overlap.
     * Note that the assertion is correct regardless of how much they actually overlap: if the
     * threads happen to serialise completely, the loser's SELECT simply finds no live row and it is
     * rejected anyway. Overlap only determines whether the row lock is genuinely exercised — see
     * {@link #theRefreshLookupTakesARowLockThatBlocksAConcurrentLookupOfTheSameRow()} for the
     * deterministic proof that the lock exists.
     * <p>
     * Without the lock this test fails with two successes: {@code outcomes} is
     * {@code [SUCCESS, SUCCESS]} and two live rows remain for the user.
     */
    @Test
    void twoConcurrentRefreshesOfTheSameTokenYieldExactlyOneSuccess() throws Exception {
        UserEntity user = persistUser("concurrent-refresh@example.com");
        TokenResponse issued = tokenService.issueTokens(user.getId(), user.getEmail());
        String stolenRefreshToken = issued.refreshToken();

        CountDownLatch startGate = new CountDownLatch(1);
        List<CompletableFuture<Outcome>> attempts = IntStream.range(0, 2)
            .mapToObj(i -> CompletableFuture.supplyAsync(() -> {
                awaitLatch(startGate);
                try {
                    tokenService.refresh(stolenRefreshToken);
                    return Outcome.REDEEMED;
                } catch (CustomException e) {
                    // anything other than CustomException propagates and fails the test loudly -
                    // e.g. a lock-acquisition failure would be a different bug, not a pass.
                    assertThat(e.getStatus()).isEqualTo(401);
                    assertThat(e.getMessage()).isEqualTo("refresh token is invalid");
                    return Outcome.REJECTED;
                }
            }, executor()))
            .toList();

        startGate.countDown();

        List<Outcome> outcomes = attempts.stream()
            .map(future -> future.orTimeout(GENEROUS_TIMEOUT_SECONDS, TimeUnit.SECONDS).join())
            .toList();

        assertThat(outcomes).containsExactlyInAnyOrder(Outcome.REDEEMED, Outcome.REJECTED);
        // corroborating state check: exactly one live row survives. Two would mean two renewable
        // session chains were minted from one refresh token.
        assertThat(liveTokensFor(user.getId())).hasSize(1);
        // and the redeemed original is revoked with a revocation instant stamped
        TokenEntity original = tokenByHash(sha256Hex(stolenRefreshToken));
        assertThat(original.isRevoked()).isTrue();
        assertThat(original.getRevokedAt()).isNotNull();
    }

    /**
     * Deterministic proof that the lookup really takes a row lock, rather than relying on threads
     * happening to interleave.
     * <p>
     * A holder thread opens a transaction, runs the finder (acquiring the lock) and keeps its
     * transaction open. A contender thread then runs the same finder in its own transaction. If the
     * SELECT took no row lock the contender would return immediately; instead it must still be
     * blocked when we check. This test fails deterministically if the {@code @Lock} annotation is
     * removed ("Expecting code to raise a throwable").
     */
    @Test
    void theRefreshLookupTakesARowLockThatBlocksAConcurrentLookupOfTheSameRow() throws Exception {
        UserEntity user = persistUser("row-lock@example.com");
        TokenResponse issued = tokenService.issueTokens(user.getId(), user.getEmail());
        String hash = sha256Hex(issued.refreshToken());

        TransactionTemplate transactionTemplate = new TransactionTemplate(transactionManager);
        CountDownLatch lockAcquired = new CountDownLatch(1);
        CountDownLatch releaseLock = new CountDownLatch(1);

        CompletableFuture<Void> holder = CompletableFuture.runAsync(() ->
            transactionTemplate.executeWithoutResult(status -> {
                Optional<TokenEntity> locked = tokenRepository.findByRefreshTokenHashAndRevokedFalse(hash);
                assertThat(locked).isPresent();
                lockAcquired.countDown();
                // keep the transaction - and therefore the row lock - open
                awaitLatch(releaseLock);
            }), executor());

        try {
            assertThat(lockAcquired.await(GENEROUS_TIMEOUT_SECONDS, TimeUnit.SECONDS)).isTrue();

            CompletableFuture<Boolean> contender = CompletableFuture.supplyAsync(() ->
                Boolean.TRUE.equals(transactionTemplate.execute(status ->
                    tokenRepository.findByRefreshTokenHashAndRevokedFalse(hash).isPresent())), executor());

            assertThatThrownBy(() -> contender.get(LOCK_WAIT_PROOF_SECONDS, TimeUnit.SECONDS))
                .as("the second lookup must block on the row lock held by the open transaction; "
                    + "without SELECT ... FOR UPDATE it would return immediately")
                .isInstanceOf(TimeoutException.class);

            releaseLock.countDown();
            holder.get(GENEROUS_TIMEOUT_SECONDS, TimeUnit.SECONDS);
            // once the lock is released the contender proceeds normally - the row was never
            // modified, so it is still live and still found.
            assertThat(contender.get(GENEROUS_TIMEOUT_SECONDS, TimeUnit.SECONDS)).isTrue();
        } finally {
            releaseLock.countDown();
        }
    }

    /**
     * Replaces the former {@code TokenServiceImplTest#refreshRejectsAlreadyRevokedToken}, which
     * stubbed the repository to return {@code Optional.empty()} and asserted "invalid" — an exact
     * duplicate of the unknown-token test that could not possibly prove anything about
     * {@code revoked=false}, since the derived query never ran. This runs the real query against a
     * real PostgreSQL, before and after revocation, with the same hash.
     */
    @Test
    void aRevokedRowIsNotReturnedByTheDerivedFinder() {
        UserEntity user = persistUser("revoked-excluded@example.com");
        TokenResponse issued = tokenService.issueTokens(user.getId(), user.getEmail());
        String hash = sha256Hex(issued.refreshToken());

        assertThat(findLiveTokenInTransaction(hash)).isPresent();

        tokenService.refresh(issued.refreshToken());

        // the row still exists and the hash still matches - only `revoked` changed, and that alone
        // must exclude it.
        assertThat(tokenByHash(hash).isRevoked()).isTrue();
        assertThat(findLiveTokenInTransaction(hash)).isEmpty();
        // and so replaying the redeemed token is indistinguishable from presenting a bogus one
        assertThatThrownBy(() -> tokenService.refresh(issued.refreshToken()))
            .isInstanceOf(CustomException.class)
            .hasMessage("refresh token is invalid");
    }

    /**
     * Fix 4, at the database level: the {@code session_id} column of the newly minted row must
     * equal the redeemed row's. Consumers see this value as {@code JwtClaims.sessionId}; if it were
     * regenerated every 15 minutes with nothing linking old to new, "revoke session X" and
     * per-session audit would be unimplementable.
     */
    @Test
    void theSessionIdIsCarriedForwardAcrossARefresh() {
        UserEntity user = persistUser("session-carry-forward@example.com");
        TokenResponse first = tokenService.issueTokens(user.getId(), user.getEmail());
        UUID originalSessionId = tokenByHash(sha256Hex(first.refreshToken())).getSessionId();

        TokenResponse refreshed = tokenService.refresh(first.refreshToken());

        TokenEntity rotated = tokenByHash(sha256Hex(refreshed.refreshToken()));
        assertThat(rotated.getSessionId()).isEqualTo(originalSessionId);
        // the credential rotated even though the session did not
        assertThat(refreshed.refreshToken()).isNotEqualTo(first.refreshToken());
        assertThat(rotated.isRevoked()).isFalse();
    }

    /**
     * The complementary half: a fresh login is a new session, so two independent calls to the
     * public {@code issueTokens(Long, String)} must produce different session ids.
     */
    @Test
    void twoIndependentLoginsGetDifferentSessionIds() {
        UserEntity user = persistUser("two-logins@example.com");

        TokenResponse first = tokenService.issueTokens(user.getId(), user.getEmail());
        TokenResponse second = tokenService.issueTokens(user.getId(), user.getEmail());

        assertThat(tokenByHash(sha256Hex(first.refreshToken())).getSessionId())
            .isNotEqualTo(tokenByHash(sha256Hex(second.refreshToken())).getSessionId());
    }

    /**
     * Fix 7c: {@code revoked_at} must actually round-trip through the migrated schema — a nullable
     * {@code TIMESTAMP WITH TIME ZONE} that is null while the row is live and stamped on revocation.
     */
    @Test
    void revokedAtIsNullWhileLiveAndStampedOnRedemption() {
        UserEntity user = persistUser("revoked-at@example.com");
        TokenResponse issued = tokenService.issueTokens(user.getId(), user.getEmail());
        String hash = sha256Hex(issued.refreshToken());

        assertThat(tokenByHash(hash).getRevokedAt()).isNull();

        tokenService.refresh(issued.refreshToken());

        TokenEntity redeemed = tokenByHash(hash);
        assertThat(redeemed.getRevokedAt()).isNotNull();
        assertThat(redeemed.getRevokedAt()).isAfterOrEqualTo(redeemed.getCreatedAt());
        // the freshly minted replacement is live and unstamped
        assertThat(liveTokensFor(user.getId()))
            .singleElement()
            .satisfies(live -> assertThat(live.getRevokedAt()).isNull());
    }

    /**
     * Fix 7a/7b at the service boundary: null, blank, unknown and already-redeemed refresh tokens
     * must all produce the identical 401, so nothing distinguishes them.
     */
    @Test
    void everyNonExpiryRefreshFailureProducesTheIdenticalUnauthorizedError() {
        UserEntity user = persistUser("uniform-failure@example.com");
        TokenResponse issued = tokenService.issueTokens(user.getId(), user.getEmail());
        tokenService.refresh(issued.refreshToken());

        List<String> tokens = List.of("", "   ", "never-issued-token", issued.refreshToken());
        for (String token : tokens) {
            assertThatThrownBy(() -> tokenService.refresh(token))
                .as("refresh(%s)", token.isBlank() ? "<blank>" : "…")
                .isInstanceOf(CustomException.class)
                .hasMessage("refresh token is invalid")
                .extracting(e -> ((CustomException) e).getStatus())
                .isEqualTo(401);
        }
        assertThatThrownBy(() -> tokenService.refresh(null))
            .isInstanceOf(CustomException.class)
            .hasMessage("refresh token is invalid");
    }

    private enum Outcome {
        REDEEMED,
        REJECTED
    }

    private UserEntity persistUser(String email) {
        return userRepository.save(UserEntity.builder()
            .email(email)
            .passwordHash("not-a-real-hash")
            .build());
    }

    /**
     * Runs the locking finder inside a transaction, which a {@code PESSIMISTIC_WRITE} lock requires.
     * Declared to return {@code Optional<TokenEntity>} explicitly because inlining the
     * {@code TransactionTemplate.execute} call into an {@code assertThat} leaves the generic
     * inference ambiguous.
     */
    private Optional<TokenEntity> findLiveTokenInTransaction(String hash) {
        return new TransactionTemplate(transactionManager).execute(status ->
            tokenRepository.findByRefreshTokenHashAndRevokedFalse(hash));
    }

    /** Deliberately avoids the locking finder so it can be called outside a transaction. */
    private TokenEntity tokenByHash(String hash) {
        return tokenRepository.findAll().stream()
            .filter(token -> token.getRefreshTokenHash().equals(hash))
            .findFirst()
            .orElseThrow(() -> new AssertionError("no token row found for hash " + hash));
    }

    private List<TokenEntity> liveTokensFor(Long userId) {
        return tokenRepository.findAll().stream()
            .filter(token -> token.getUserId().equals(userId) && !token.isRevoked())
            .toList();
    }

    private static void awaitLatch(CountDownLatch latch) {
        try {
            if (!latch.await(GENEROUS_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                throw new IllegalStateException("timed out waiting for latch");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("interrupted while waiting for latch", e);
        }
    }

    private static String sha256Hex(String value) {
        try {
            return HexFormat.of().formatHex(
                MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
