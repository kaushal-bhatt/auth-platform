package com.authplatform.auth.service.impl;

import com.authplatform.auth.entity.PasskeyChallengeEntity;
import com.authplatform.auth.exception.CustomException;
import com.authplatform.auth.repository.PasskeyChallengeRepository;
import com.webauthn4j.data.client.challenge.Challenge;
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

import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
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
 * Integration coverage for {@link PasskeyChallengeHelper#consumeChallenge(String)} against a real
 * PostgreSQL, because the invariant being protected - a passkey challenge is redeemable
 * <em>exactly once</em> - lives in the database's locking and visibility rules and cannot be
 * demonstrated with a mocked repository. Mirrors {@code TokenServiceImplIntegrationTest}, which
 * proves the equivalent invariant for refresh-token rotation.
 */
@Testcontainers
@SpringBootTest
class PasskeyChallengeHelperIntegrationTest {

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

    @Autowired
    private PasskeyChallengeHelper challengeHelper;

    @Autowired
    private PasskeyChallengeRepository challengeRepository;

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
     * THE critical test. Two simultaneous consumptions of the same challenge must yield exactly one
     * success and one rejection.
     * <p>
     * Both threads park on a {@link CountDownLatch} and are released together to maximise overlap.
     * The assertion is correct regardless of how much they actually overlap: if the threads happen
     * to serialise completely, the loser's lookup simply finds no live row (already deleted) and is
     * rejected anyway. Overlap only determines whether the row lock is genuinely exercised - see
     * {@link #theChallengeLookupTakesARowLockThatBlocksAConcurrentLookupOfTheSameRow()} for the
     * deterministic proof that the lock exists.
     * <p>
     * Honesty note on overlap: this test was run against a negative control (the {@code @Lock}
     * annotation temporarily removed from {@code PasskeyChallengeRepository#findByChallenge}) and
     * failed 3 runs out of 3 - not with a clean duplicate {@code CONSUMED}/{@code CONSUMED} result,
     * but with an unhandled {@code ObjectOptimisticLockingFailureException} ("Row was updated or
     * deleted by another transaction") surfacing from the second thread's {@code delete()} call.
     * That confirms the threads do genuinely overlap: both SELECTs saw the live row before either
     * DELETE committed, which is exactly the race the lock exists to prevent. It also shows that
     * even without duplicate redemption, the unlocked version is still broken - it throws an
     * internal Hibernate/Spring exception instead of the uniform {@code CustomException} every
     * other failure path produces, which the assertion above deliberately does not catch (see the
     * comment on {@code assertThat(e.getStatus())} below) so this class of regression fails loudly.
     * See the class javadoc of {@code PasskeyChallengeRepository#findByChallenge} for why the lock
     * is what prevents both problems.
     */
    @Test
    void twoConcurrentConsumeChallengeCallsForTheSameChallengeYieldExactlyOneSuccess() throws Exception {
        Challenge challenge = challengeHelper.issueChallenge(42L);
        String encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(challenge.getValue());

        CountDownLatch startGate = new CountDownLatch(1);
        List<CompletableFuture<Outcome>> attempts = IntStream.range(0, 2)
            .mapToObj(i -> CompletableFuture.supplyAsync(() -> {
                awaitLatch(startGate);
                try {
                    Long userId = challengeHelper.consumeChallenge(encoded);
                    assertThat(userId).isEqualTo(42L);
                    return Outcome.CONSUMED;
                } catch (CustomException e) {
                    // anything other than CustomException propagates and fails the test loudly.
                    assertThat(e.getStatus()).isEqualTo(400);
                    return Outcome.REJECTED;
                }
            }, executor()))
            .toList();

        startGate.countDown();

        List<Outcome> outcomes = attempts.stream()
            .map(future -> future.orTimeout(GENEROUS_TIMEOUT_SECONDS, TimeUnit.SECONDS).join())
            .toList();

        assertThat(outcomes).containsExactlyInAnyOrder(Outcome.CONSUMED, Outcome.REJECTED);
        // corroborating state check: the row is gone. Two CONSUMED outcomes would mean the same
        // challenge (and therefore the same WebAuthn ceremony) was accepted twice.
        assertThat(findChallengeInTransaction(encoded)).isEmpty();
    }

    /**
     * Deterministic proof that the lookup really takes a row lock, rather than relying on threads
     * happening to interleave. Mirrors
     * {@code TokenServiceImplIntegrationTest#theRefreshLookupTakesARowLockThatBlocksAConcurrentLookupOfTheSameRow}.
     * <p>
     * A holder thread opens a transaction, runs the finder (acquiring the lock) and keeps its
     * transaction open. A contender thread then runs the same finder in its own transaction. If the
     * lookup took no row lock the contender would return immediately; instead it must still be
     * blocked when checked. This test fails deterministically if the {@code @Lock} annotation is
     * removed ("Expecting code to raise a throwable").
     */
    @Test
    void theChallengeLookupTakesARowLockThatBlocksAConcurrentLookupOfTheSameRow() throws Exception {
        Challenge challenge = challengeHelper.issueChallenge(55L);
        String encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(challenge.getValue());

        TransactionTemplate transactionTemplate = new TransactionTemplate(transactionManager);
        CountDownLatch lockAcquired = new CountDownLatch(1);
        CountDownLatch releaseLock = new CountDownLatch(1);

        CompletableFuture<Void> holder = CompletableFuture.runAsync(() ->
            transactionTemplate.executeWithoutResult(status -> {
                Optional<PasskeyChallengeEntity> locked = challengeRepository.findByChallenge(encoded);
                assertThat(locked).isPresent();
                lockAcquired.countDown();
                // keep the transaction - and therefore the row lock - open
                awaitLatch(releaseLock);
            }), executor());

        try {
            assertThat(lockAcquired.await(GENEROUS_TIMEOUT_SECONDS, TimeUnit.SECONDS)).isTrue();

            CompletableFuture<Boolean> contender = CompletableFuture.supplyAsync(() ->
                Boolean.TRUE.equals(transactionTemplate.execute(status ->
                    challengeRepository.findByChallenge(encoded).isPresent())), executor());

            assertThatThrownBy(() -> contender.get(LOCK_WAIT_PROOF_SECONDS, TimeUnit.SECONDS))
                .as("the second lookup must block on the row lock held by the open transaction; "
                    + "without a pessimistic lock it would return immediately")
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
     * Pins the answer to "does the delete survive when the expiry exception propagates". An
     * expired challenge is deliberately deleted before the expiry check throws (see
     * {@link PasskeyChallengeHelper#consumeChallenge(String)}'s javadoc) - this proves that delete
     * actually commits by observing that a second attempt to consume the same challenge value sees
     * "unknown challenge", not "expired challenge" again. If the {@code REQUIRES_NEW} split were
     * removed and the delete instead rolled back with the rest of the transaction, the row would
     * survive and the second attempt would still find it and report "expired" a second (and
     * indefinite number of) time(s).
     */
    @Test
    void anExpiredChallengeIsDeletedEvenThoughConsumeThrows() {
        PasskeyChallengeEntity expired = PasskeyChallengeEntity.builder()
            .userId(99L)
            .challenge("already-expired-challenge-value")
            .expiresAt(Instant.now().minusSeconds(60))
            .build();
        challengeRepository.save(expired);

        assertThatThrownBy(() -> challengeHelper.consumeChallenge("already-expired-challenge-value"))
            .isInstanceOf(CustomException.class)
            .hasMessageContaining("expired");

        // the row must be gone - not just logically expired but actually deleted, despite the
        // exception thrown above.
        assertThat(findChallengeInTransaction("already-expired-challenge-value")).isEmpty();

        // consuming again must fail with "unknown", never "expired" a second time - that would mean
        // the row was never really deleted (i.e. the delete rolled back).
        assertThatThrownBy(() -> challengeHelper.consumeChallenge("already-expired-challenge-value"))
            .isInstanceOf(CustomException.class)
            .hasMessageContaining("unknown");
    }

    private enum Outcome {
        CONSUMED,
        REJECTED
    }

    /**
     * Runs the locking finder inside a transaction, which {@code @Lock(PESSIMISTIC_WRITE)} requires
     * even for a plain verification read - without an active transaction Spring Data throws
     * {@code InvalidDataAccessApiUsageException} (caused by {@code TransactionRequiredException}).
     */
    private Optional<PasskeyChallengeEntity> findChallengeInTransaction(String challenge) {
        return new TransactionTemplate(transactionManager).execute(status ->
            challengeRepository.findByChallenge(challenge));
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
}
