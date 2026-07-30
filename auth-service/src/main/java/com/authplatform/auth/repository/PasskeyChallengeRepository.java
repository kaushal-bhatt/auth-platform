package com.authplatform.auth.repository;

import com.authplatform.auth.entity.PasskeyChallengeEntity;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;

import java.util.Optional;
import java.util.UUID;

public interface PasskeyChallengeRepository extends JpaRepository<PasskeyChallengeEntity, UUID> {

    /**
     * Looks up a passkey challenge by its base64url value, taking a {@code PESSIMISTIC_WRITE} row
     * lock. Mirrors {@code TokenRepository#findByRefreshTokenHashAndRevokedFalse} - see that
     * method's javadoc for the full mechanics of why a row lock, rather than a {@code @Version}
     * column, is what makes concurrent consumption serialise on PostgreSQL.
     * <p>
     * The lock is load-bearing here too: a WebAuthn challenge must be redeemable <em>exactly
     * once</em>. {@code PasskeyChallengeHelper#consumeChallenge} deletes the row inside a
     * {@code REQUIRES_NEW} transaction built around this finder. Without the lock, two concurrent
     * calls for the same challenge could both {@code SELECT} the row before either deletes it -
     * plain {@code SELECT} takes no row lock under READ COMMITTED - and both would then treat the
     * challenge as successfully consumed, a replay window in exactly the shape the refresh-token
     * fix closed. With the lock, the second transaction's {@code SELECT ... FOR NO KEY UPDATE}
     * blocks until the first's {@code REQUIRES_NEW} transaction commits the delete; PostgreSQL then
     * re-evaluates the predicate against the now-committed (deleted) row and the blocked query
     * returns empty, so the loser correctly sees "unknown challenge" rather than a duplicate
     * success.
     * <p>
     * A pessimistic lock only has effect inside a transaction, and Spring Data throws if one is
     * absent - every caller must run this through a transactional boundary, which
     * {@code PasskeyChallengeHelper#consumeChallenge} does via its {@code REQUIRES_NEW}
     * {@code TransactionTemplate}.
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    Optional<PasskeyChallengeEntity> findByChallenge(String challenge);
}
