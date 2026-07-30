package com.authplatform.auth.repository;

import com.authplatform.auth.entity.TokenEntity;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;

import java.util.Optional;
import java.util.UUID;

public interface TokenRepository extends JpaRepository<TokenEntity, UUID> {

    /**
     * Looks up a live (non-revoked) refresh token row, taking a {@code PESSIMISTIC_WRITE} row lock.
     * On PostgreSQL, Hibernate renders that as
     * {@code select ... where refresh_token_hash=? and not(revoked) for no key update} (verified
     * from the emitted SQL — Hibernate's PostgreSQL dialect prefers {@code FOR NO KEY UPDATE} over
     * {@code FOR UPDATE} for a write lock). That is exactly the strength required here:
     * {@code FOR NO KEY UPDATE} conflicts with itself and with the implicit row lock an
     * {@code UPDATE} takes, so two concurrent redemptions of the same row serialise, while leaving
     * foreign-key {@code KEY SHARE} readers unblocked.
     * <p>
     * The lock is load-bearing, not an optimisation. Refresh-token rotation must redeem a
     * refresh token <em>exactly once</em>. Without the lock the redemption in
     * {@code TokenServiceImpl#refresh} is an unguarded read-then-write: Hibernate issues
     * {@code SELECT ... WHERE refresh_token_hash=? AND revoked=false} and then
     * {@code UPDATE token SET revoked=true WHERE id=?} — note the UPDATE predicate is the
     * primary key alone and does <em>not</em> re-check {@code revoked=false}. Under
     * PostgreSQL's default READ COMMITTED isolation, and with no {@code @Version} on
     * {@link TokenEntity}, two concurrent transactions could both SELECT the same row and both
     * see {@code revoked=false}; the second UPDATE would still match on {@code id} after the
     * first committed, so both would succeed and mint a fresh token pair from a single refresh
     * token — two independent, indefinitely renewable session chains from one credential.
     * <p>
     * With the row lock, the second transaction blocks instead of reading. When the first commits
     * with {@code revoked=true}, PostgreSQL re-evaluates the query predicate against the newly
     * committed row version before returning it (EvalPlanQual), so the row no longer satisfies
     * {@code revoked=false} and the loser gets an empty result — and therefore the same 401 as any
     * other invalid refresh token. This is verified by
     * {@code TokenServiceImplIntegrationTest#twoConcurrentRefreshesOfTheSameTokenYieldExactlyOneSuccess},
     * which reproduces {@code [REDEEMED, REDEEMED]} when this annotation is removed.
     * <p>
     * A pessimistic lock only has effect inside a transaction, and Spring Data throws if one is
     * absent. Every caller must therefore be transactional; {@code TokenServiceImpl#refresh} is
     * annotated {@code @Transactional} and is invoked through the Spring proxy.
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    Optional<TokenEntity> findByRefreshTokenHashAndRevokedFalse(String refreshTokenHash);
}
