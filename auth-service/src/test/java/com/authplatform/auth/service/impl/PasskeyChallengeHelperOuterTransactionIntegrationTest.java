package com.authplatform.auth.service.impl;

import com.authplatform.auth.entity.PasskeyChallengeEntity;
import com.authplatform.auth.repository.PasskeyChallengeRepository;
import com.webauthn4j.data.client.challenge.Challenge;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.stereotype.Component;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.Base64;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Task 14 mandatory addition (a). Every existing caller of
 * {@link PasskeyChallengeHelper#consumeChallenge(String)} before this task (e.g. tests in
 * {@code PasskeyChallengeHelperIntegrationTest}) calls it with no outer transaction of its own
 * active, or from a plain {@link TransactionTemplate} used purely as a verification probe.
 * {@code PasskeyRegistrationServiceImpl#completeRegistration} is the first <em>real</em> caller
 * that is itself {@code @Transactional} - i.e. the first caller where {@code consumeChallenge}'s
 * internal {@code REQUIRES_NEW} find+delete genuinely nests inside another active proxy-managed
 * transaction. That shape was untested before this class.
 * <p>
 * {@link OuterTransactionCaller} stands in for {@code completeRegistration}: a real
 * {@code @Transactional} Spring bean method that calls {@code consumeChallenge} and then either
 * returns normally or throws, exactly as {@code completeRegistration} does when a later step
 * (attestation validation, duplicate-credential check) fails after the challenge has already been
 * consumed.
 */
@Testcontainers
@SpringBootTest
@Import(PasskeyChallengeHelperOuterTransactionIntegrationTest.OuterTransactionCaller.class)
class PasskeyChallengeHelperOuterTransactionIntegrationTest {

    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:16-alpine");

    @DynamicPropertySource
    static void configureDatasource(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
    }

    @Autowired
    private OuterTransactionCaller outerTransactionCaller;

    @Autowired
    private PasskeyChallengeHelper passkeyChallengeHelper;

    @Autowired
    private PasskeyChallengeRepository passkeyChallengeRepository;

    @Autowired
    private PlatformTransactionManager transactionManager;

    /**
     * Baseline: consuming a challenge from inside a genuinely active outer {@code @Transactional}
     * method must still succeed and return the bound userId, exactly as it does with no outer
     * transaction.
     */
    @Test
    void consumeChallengeSucceedsInsideAGenuinelyActiveOuterTransaction() {
        Challenge challenge = passkeyChallengeHelper.issueChallenge(701L);
        String encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(challenge.getValue());

        Long userId = outerTransactionCaller.consumeThenReturn(encoded);

        assertThat(userId).isEqualTo(701L);
        assertThat(findInTransaction(encoded)).isEmpty();
    }

    /**
     * THE critical test for mandatory addition (a): single-use consumption must win over ceremony
     * failure. If the outer transaction (standing in for {@code completeRegistration}) goes on to
     * roll back - because, say, attestation validation failed after the challenge was consumed -
     * the challenge must stay deleted. If the {@code REQUIRES_NEW} split inside
     * {@code consumeChallenge} were ever broken (e.g. accidentally made to participate in the
     * caller's transaction), the delete would roll back along with the outer transaction and the
     * challenge would still be sitting there, consumable a second time - defeating single-use
     * enforcement across the exact case this task introduces: an outer transaction that can itself
     * fail after consuming the challenge.
     */
    @Test
    void challengeStaysDeletedWhenTheOuterTransactionSubsequentlyRollsBack() {
        Challenge challenge = passkeyChallengeHelper.issueChallenge(702L);
        String encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(challenge.getValue());

        assertThatThrownBy(() -> outerTransactionCaller.consumeThenRollback(encoded))
            .isInstanceOf(OuterTransactionCaller.SimulatedCeremonyFailure.class);

        // the row must be gone despite the outer transaction's rollback - proving the
        // REQUIRES_NEW delete already committed independently of it.
        assertThat(findInTransaction(encoded)).isEmpty();

        // and single-use is provably intact: a second attempt to consume the same challenge value
        // must see "unknown", never succeed a second time and never see "expired" (which would
        // mean the row was never deleted at all).
        assertThatThrownBy(() -> passkeyChallengeHelper.consumeChallenge(encoded))
            .hasMessageContaining("unknown");
    }

    private Optional<PasskeyChallengeEntity> findInTransaction(String challenge) {
        return new TransactionTemplate(transactionManager).execute(status ->
            passkeyChallengeRepository.findByChallenge(challenge));
    }

    @Component
    static class OuterTransactionCaller {

        private final PasskeyChallengeHelper passkeyChallengeHelper;

        OuterTransactionCaller(PasskeyChallengeHelper passkeyChallengeHelper) {
            this.passkeyChallengeHelper = passkeyChallengeHelper;
        }

        @Transactional
        public Long consumeThenReturn(String challenge) {
            return passkeyChallengeHelper.consumeChallenge(challenge);
        }

        @Transactional
        public Long consumeThenRollback(String challenge) {
            passkeyChallengeHelper.consumeChallenge(challenge);
            throw new SimulatedCeremonyFailure();
        }

        static class SimulatedCeremonyFailure extends RuntimeException {
        }
    }
}
