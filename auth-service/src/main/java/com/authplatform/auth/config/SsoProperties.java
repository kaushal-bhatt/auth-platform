package com.authplatform.auth.config;

import jakarta.annotation.PostConstruct;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Relying parties allowed to log users in through this service, and the settings of the
 * redirect flow itself.
 * <p>
 * Configuration rather than a database table because there is one client and it is part of the
 * deployment, not user data: a table would need an admin UI to be useful and a migration to
 * change, where this is a line in {@code .env}. Add a table when a second party needs to
 * register itself without a deploy.
 * <p>
 * <strong>No clients configured means the flow is off.</strong> That is the right default for a
 * public repository — a fresh checkout exposes no login surface for a relying party nobody has
 * declared.
 */
@Getter
@Setter
@ConfigurationProperties(prefix = "auth-platform.sso")
public class SsoProperties {

    /** Keyed by {@code client_id}. Empty by default — see the class javadoc. */
    private Map<String, Client> clients = new LinkedHashMap<>();

    /**
     * How long an authorisation code stays redeemable.
     * <p>
     * Short on purpose. The code travels in a redirect URL and so ends up in browser history and
     * in {@code Referer} headers; the window in which a copy is worth anything should be about
     * as long as it takes the relying party's server to redeem it, which is one round trip.
     */
    private int codeTtlSeconds = 60;

    /**
     * How long a redeemed or expired code row is kept before the purge removes it. Purely for
     * being able to look at recent activity — nothing reads these rows once consumed.
     */
    private int codeRetentionMinutes = 60;

    @Getter
    @Setter
    public static class Client {

        /**
         * Shared secret proving a token request really comes from this relying party. It never
         * leaves that party's server, which is the whole reason the browser is handed a code
         * rather than a token.
         */
        private String secret;

        /**
         * Exact URIs this client may be redirected back to. Matched by full string equality,
         * never by prefix or host: a prefix match on {@code https://wekt.in/} would happily
         * accept {@code https://wekt.in/@evil.example}, and a host match ignores the path
         * entirely. An open redirect here hands authorisation codes to whoever asks for them,
         * which is the single most exploited flaw in this kind of flow.
         */
        private List<String> redirectUris = new ArrayList<>();

        /**
         * Role the user must hold for this client, or {@code null} to accept any authenticated
         * user.
         * <p>
         * Set it. Registration on the demo is open to anyone, so without a required role
         * "authenticated" means "signed up thirty seconds ago", and the relying party would be
         * letting strangers in while looking like it checked something.
         */
        private String requiredRole;
    }

    /**
     * Fails startup on a client that is configured but unusable, rather than at the first login
     * attempt. A half-declared client is a deployment mistake, and the failure it causes
     * otherwise — a redirect that dead-ends much later, in someone's browser — is far harder to
     * connect back to its cause than a startup message naming the property.
     */
    @PostConstruct
    void validate() {
        clients.forEach((clientId, client) -> {
            if (client.getSecret() == null || client.getSecret().isBlank()) {
                throw new IllegalStateException(
                    "auth-platform.sso.clients." + clientId + ".secret is not set");
            }
            if (client.getRedirectUris() == null || client.getRedirectUris().isEmpty()) {
                throw new IllegalStateException(
                    "auth-platform.sso.clients." + clientId + ".redirect-uris is empty; "
                        + "a client with no registered redirect URI can never complete a login");
            }
            client.getRedirectUris().forEach(uri -> {
                if (!uri.startsWith("https://") && !uri.startsWith("http://localhost")) {
                    throw new IllegalStateException(
                        "auth-platform.sso.clients." + clientId + ".redirect-uris contains a "
                            + "non-https URI; an authorisation code sent over plain http is "
                            + "readable by anything on the path (http://localhost is allowed "
                            + "for development)");
                }
            });
        });
    }
}
