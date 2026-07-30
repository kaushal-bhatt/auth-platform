package com.authplatform.auth.service.impl;

import com.authplatform.auth.entity.PasskeyChallengeEntity;
import com.authplatform.auth.exception.CustomException;
import com.authplatform.auth.repository.PasskeyChallengeRepository;
import com.webauthn4j.data.client.challenge.Challenge;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.TransactionStatus;

import java.time.Instant;
import java.util.Base64;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit-level coverage with a fully mocked repository. {@link PasskeyChallengeHelper} now takes a
 * {@link PlatformTransactionManager} as well as the repository, because {@code consumeChallenge}
 * runs its find+delete inside a {@code REQUIRES_NEW} transaction (see that method's javadoc) - the
 * transaction manager here is a Mockito mock that hands back a mock {@link TransactionStatus} so
 * {@code TransactionTemplate} can drive the callback synchronously without a real database. None
 * of the four scenarios below exercise real transactional or locking behaviour; that is covered by
 * {@code PasskeyChallengeHelperIntegrationTest} against a real PostgreSQL.
 */
class PasskeyChallengeHelperTest {

    private PasskeyChallengeRepository challengeRepository;
    private PasskeyChallengeHelper helper;

    @BeforeEach
    void setUp() {
        challengeRepository = mock(PasskeyChallengeRepository.class);
        when(challengeRepository.save(any(PasskeyChallengeEntity.class)))
            .thenAnswer(invocation -> invocation.getArgument(0));

        PlatformTransactionManager transactionManager = mock(PlatformTransactionManager.class);
        when(transactionManager.getTransaction(any(TransactionDefinition.class)))
            .thenReturn(mock(TransactionStatus.class));

        helper = new PasskeyChallengeHelper(challengeRepository, transactionManager);
    }

    @Test
    void issueChallengePersistsAndReturnsMatchingValue() {
        Challenge challenge = helper.issueChallenge(7L);

        String expectedEncoded = Base64.getUrlEncoder().withoutPadding().encodeToString(challenge.getValue());
        verify(challengeRepository).save(argThat(entity ->
            entity.getUserId().equals(7L) && entity.getChallenge().equals(expectedEncoded)));
    }

    @Test
    void consumeChallengeReturnsUserIdAndDeletesRow() {
        PasskeyChallengeEntity entity = PasskeyChallengeEntity.builder()
            .userId(7L)
            .challenge("abc123")
            .expiresAt(Instant.now().plusSeconds(60))
            .createdAt(Instant.now())
            .build();
        when(challengeRepository.findByChallenge("abc123")).thenReturn(Optional.of(entity));

        Long userId = helper.consumeChallenge("abc123");

        assertThat(userId).isEqualTo(7L);
        verify(challengeRepository).delete(entity);
    }

    @Test
    void consumeChallengeRejectsUnknownChallenge() {
        when(challengeRepository.findByChallenge("missing")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> helper.consumeChallenge("missing"))
            .isInstanceOf(CustomException.class);
    }

    @Test
    void consumeChallengeRejectsExpiredChallenge() {
        PasskeyChallengeEntity entity = PasskeyChallengeEntity.builder()
            .userId(7L)
            .challenge("expired-one")
            .expiresAt(Instant.now().minusSeconds(60))
            .createdAt(Instant.now())
            .build();
        when(challengeRepository.findByChallenge("expired-one")).thenReturn(Optional.of(entity));

        assertThatThrownBy(() -> helper.consumeChallenge("expired-one"))
            .isInstanceOf(CustomException.class)
            .hasMessageContaining("expired");
    }
}
