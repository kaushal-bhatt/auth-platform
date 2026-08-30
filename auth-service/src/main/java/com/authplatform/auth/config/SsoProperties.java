package com.authplatform.auth.config;

import jakarta.annotation.PostConstruct;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

/**
 * The relying party allowed to sign users in through this service, and the settings of the
 * redirect flow itself.
 * <p>
 * <strong>One client, deliberately flat.</strong> This began as a {@code Map<String, Client>}
 * keyed by client id, which reads better and does not work: Spring cannot bind a map from
 * environment variables when the prefix contains a dash. Given
 * {@code AUTH_PLATFORM_SSO_CLIENTS_PORTFOLIO_SECRET} the binder has no way to recover which
 * underscores were dots and which were dashes, so it cannot know the key is {@code portfolio} —
 * it silently binds nothing and every request is answered "unknown client". Named properties do
 * not have that problem, because the binder is looking for a name it already knows.
 * <p>
 * Since there is exactly one relying party, the map was speculative generality that also
 * happened to be unbindable. A second one belongs in a database table with somewhere to
 * register itself, not in a wider config shape.
 * <p>
 * <strong>No secret means the flow is off.</strong> The right default for a public repository:
 * a fresh checkout exposes no login surface for a client nobody declared.
 */
@Getter
@Setter
@ConfigurationProperties(prefix = "auth-platform.sso")
public class SsoProperties {

    /** Identifier the relying party sends as {@code client_id}. */
    private String clientId = "portfolio";

    /**
     * Shared secret proving a token request really comes from that relying party. It never
     * leaves their server, which is the whole reason the browser is handed a code rather than a
     * token. Blank switches the flow off entirely.
     */
    private String clientSecret;

    /**
     * Exact URIs the client may be redirected back to, comma-separated in configuration.
     * <p>
     * Matched by full string equality, never by prefix or host: a prefix match on
     * {@code https://wekt.in/} would happily accept {@code https://wekt.in/@evil.example}, and a
     * host match ignores the path entirely. An open redirect here hands authorisation codes to
     * whoever asks for them, which is the single most exploited flaw in this kind of flow.
     */
    private List<String> redirectUris = new ArrayList<>();

    /**
     * Role the user must hold, or blank to accept any authenticated user.
     * <p>
     * Set it. Registration is open on the demo, so without a required role "authenticated" means
     * "signed up thirty seconds ago", and the relying party would be letting strangers in while
     * looking like it checked something.
     */
    private String requiredRole;

    /**
     * How long an authorisation code stays redeemable.
     * <p>
     * Short on purpose. The code travels in a redirect URL and so ends up in browser history and
     * in {@code Referer} headers; the window in which a copy is worth anything should be about
     * as long as it takes the relying party's server to redeem it, which is one round trip.
     */
    private int codeTtlSeconds = 60;

    /**
     * How long a redeemed or expired code row is kept before the purge removes it. Purely so
     * recent activity can be looked at — nothing reads these rows once consumed.
     */
    private int codeRetentionMinutes = 60;

    /** True when a relying party is configured at all. */
    public boolean isEnabled() {
        return clientSecret != null && !clientSecret.isBlank();
    }

    /**
     * Fails startup on a client that is configured but unusable, rather than at the first login
     * attempt. A half-declared client is a deployment mistake, and the failure it causes
     * otherwise — a redirect that dead-ends much later, in someone's browser — is far harder to
     * connect back to its cause than a startup message naming the property.
     */
    @PostConstruct
    void validate() {
        if (!isEnabled()) {
            return;
        }
        if (clientId == null || clientId.isBlank()) {
            throw new IllegalStateException("auth-platform.sso.client-id is blank");
        }
        if (redirectUris.isEmpty()) {
            throw new IllegalStateException(
                "auth-platform.sso.redirect-uris is empty; a client with no registered redirect "
                    + "URI can never complete a login");
        }
        redirectUris.forEach(uri -> {
            if (!uri.startsWith("https://") && !uri.startsWith("http://localhost")) {
                throw new IllegalStateException(
                    "auth-platform.sso.redirect-uris contains a non-https URI; an authorisation "
                        + "code sent over plain http is readable by anything on the path "
                        + "(http://localhost is allowed for development)");
            }
        });
    }
}
