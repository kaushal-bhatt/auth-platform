package com.authplatform.auth.service.impl;

import com.authplatform.auth.entity.PasskeyChallengeEntity;
import com.authplatform.auth.exception.CustomException;
import com.authplatform.auth.repository.PasskeyChallengeRepository;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;

@Component
public class PasskeyChallengeHelper {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final long CHALLENGE_TTL_MINUTES = 5;

    private final PasskeyChallengeRepository challengeRepository;

    /**
     * Runs the find-lock-delete step of {@link #consumeChallenge(String)} in its own transaction,
     * independent of anything the caller does afterward. See that method's javadoc for why this is
     * load-bearing rather than an optimisation.
     */
    private final TransactionTemplate requiresNewTransactionTemplate;

    public PasskeyChallengeHelper(PasskeyChallengeRepository challengeRepository,
                                   PlatformTransactionManager transactionManager) {
        this.challengeRepository = challengeRepository;
        this.requiresNewTransactionTemplate = new TransactionTemplate(transactionManager);
        this.requiresNewTransactionTemplate.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
    }

    /**
     * Issues a single-use, 5-minute-TTL WebAuthn challenge bound to {@code userId}.
     * <p>
     * {@code createdAt} is stamped by {@link PasskeyChallengeEntity}'s {@code @PrePersist}
     * lifecycle callback, matching {@code TokenEntity}/{@code CertificateEntity} - it is not set
     * here.
     */
    public Challenge issueChallenge(Long userId) {
        byte[] value = new byte[32];
        SECURE_RANDOM.nextBytes(value);
        String encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(value);

        PasskeyChallengeEntity entity = PasskeyChallengeEntity.builder()
            .userId(userId)
            .challenge(encoded)
            .expiresAt(Instant.now().plus(CHALLENGE_TTL_MINUTES, ChronoUnit.MINUTES))
            .build();
        challengeRepository.save(entity);

        return new DefaultChallenge(encoded);
    }

    /**
     * Consumes (redeems) a challenge exactly once, returning the bound userId.
     * <p>
     * Two things must both be true for single-use enforcement to actually hold, and neither is
     * free:
     * <ol>
     *   <li><b>The find-then-delete must be race-free.</b> {@link PasskeyChallengeRepository
     *   #findByChallenge} takes a {@code PESSIMISTIC_WRITE} row lock (mirroring
     *   {@code TokenRepository#findByRefreshTokenHashAndRevokedFalse}), so two concurrent calls for
     *   the same challenge serialise: the loser's locked {@code SELECT} blocks until the winner's
     *   transaction commits the delete, then sees no row and fails with "unknown challenge" rather
     *   than also succeeding.</li>
     *   <li><b>The delete must survive even when this method goes on to throw.</b> An expired
     *   challenge is deliberately burned (deleted) rather than left around to retry - so the delete
     *   happens before the expiry check, and the expiry check throws afterward. If both ran inside
     *   one ordinary {@code @Transactional} method, that throw would roll back the <em>whole</em>
     *   transaction, undoing the delete the "expired" branch just relied on having already
     *   happened - leaving the expired row in place to be retried indefinitely. The find+delete is
     *   therefore run inside {@link #requiresNewTransactionTemplate}'s {@code REQUIRES_NEW}
     *   transaction, which commits (and releases the row lock) before this method ever reaches the
     *   expiry check, so the later throw cannot unwind it.</li>
     * </ol>
     */
    public Long consumeChallenge(String base64UrlChallenge) {
        PasskeyChallengeEntity entity = requiresNewTransactionTemplate.execute(status -> {
            PasskeyChallengeEntity found = challengeRepository.findByChallenge(base64UrlChallenge)
                .orElseThrow(() -> new CustomException(400, "unknown or expired passkey challenge"));
            challengeRepository.delete(found);
            return found;
        });

        if (entity.getExpiresAt().isBefore(Instant.now())) {
            throw new CustomException(400, "passkey challenge has expired");
        }
        return entity.getUserId();
    }
}
