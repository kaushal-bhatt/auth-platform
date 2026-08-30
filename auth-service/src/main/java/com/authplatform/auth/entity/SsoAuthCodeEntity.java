package com.authplatform.auth.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;
import java.util.UUID;

/**
 * A single-use authorisation code from the SSO redirect flow.
 * <p>
 * The code itself travels in a redirect URL, which means it lands in browser history, in the
 * {@code Referer} header of the next request, and in the access log of every proxy on the way.
 * That is survivable only because a code is worth nothing on its own: it is redeemable exactly
 * once, expires in about a minute, and cannot be exchanged without the client secret, which
 * never leaves the relying party's server. An access token in that position would have none of
 * those properties, which is why the flow hands back a code instead.
 */
@Entity
@Table(name = "sso_auth_code", schema = "auth")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SsoAuthCodeEntity {

    @Id
    @GeneratedValue
    private UUID id;

    /**
     * SHA-256 of the code, never the code. Someone holding a database dump must not come away
     * with anything redeemable — the same reason {@link TokenEntity} stores only a hash.
     */
    @Column(name = "code_hash", nullable = false, unique = true)
    private String codeHash;

    @Column(name = "client_id", nullable = false)
    private String clientId;

    @Column(name = "user_id", nullable = false)
    private Long userId;

    /**
     * The redirect URI this code was issued against. Redemption requires the same value, so a
     * code obtained for one registered URI cannot be redeemed while claiming another.
     */
    @Column(name = "redirect_uri", nullable = false)
    private String redirectUri;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "consumed", nullable = false)
    private boolean consumed;

    /**
     * When the code was redeemed, or {@code null} while it is still unused. Kept alongside the
     * boolean because a code presented a second time is worth being able to place in time.
     */
    @Column(name = "consumed_at")
    private Instant consumedAt;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @PrePersist
    protected void onCreate() {
        this.createdAt = Instant.now();
    }
}
