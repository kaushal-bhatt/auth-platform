package com.authplatform.auth.repository;

import com.authplatform.auth.entity.SsoAuthCodeEntity;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

public interface SsoAuthCodeRepository extends JpaRepository<SsoAuthCodeEntity, UUID> {

    /**
     * Looks up an unredeemed code, taking a {@code PESSIMISTIC_WRITE} row lock — the same
     * pattern, and for the same reason, as
     * {@link TokenRepository#findByRefreshTokenHashAndRevokedFalse}.
     * <p>
     * "Single use" has to hold under concurrency or it is not a property at all. Redemption is a
     * read-then-write: select the row where {@code consumed=false}, then update it by primary
     * key. Under PostgreSQL's default READ COMMITTED isolation two requests presenting the same
     * code could both read it as unconsumed and both go on to mint a token pair, which is
     * precisely the replay this table exists to prevent. With the lock the second request blocks,
     * and once the first commits, PostgreSQL re-evaluates the predicate against the new row
     * version, so the loser sees no row and gets the same rejection as an unknown code.
     * <p>
     * A pessimistic lock has no effect outside a transaction and Spring Data rejects it, so every
     * caller must be transactional.
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    Optional<SsoAuthCodeEntity> findByCodeHashAndConsumedFalse(String codeHash);

    /**
     * Deletes codes that are past their expiry, redeemed or not.
     * <p>
     * Codes live about a minute but rows would accumulate for the life of the deployment. The
     * cutoff is passed in rather than computed here so the caller decides how long a redeemed
     * code stays visible for debugging.
     */
    @Modifying
    @Query("delete from SsoAuthCodeEntity c where c.expiresAt < :cutoff")
    int deleteExpiredBefore(@Param("cutoff") Instant cutoff);
}
