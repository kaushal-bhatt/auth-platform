# auth-platform

A standalone, generic JWT + passkey (WebAuthn) authentication platform, decoupled from any
specific product or vendor integration. Two independent Gradle modules:

- **auth-jwt-lib** — an importable Spring Boot library any service adds as a dependency to
  verify JWTs issued by an OIDC-style RS256 issuer, via a standard RFC 7517 JWKS endpoint.
  It has no dependency on auth-service — it works against any issuer that publishes a standard
  JWKS document.
- **auth-service** — a runnable Spring Boot identity provider: registration, password login,
  passkey (WebAuthn) registration/login, refresh tokens, and the JWKS endpoint itself.

The two modules are proven to interoperate purely over that public JWKS HTTP contract by
`auth-service/src/test/java/com/authplatform/auth/JwtLibInteropTest.java`, which runs a real
instance of auth-service, registers and logs in over real HTTP, and verifies the resulting token
with auth-jwt-lib's real verifier fetching the service's own live `/.well-known/jwks.json` — no
mocks anywhere in that path.

## Live demo & deployment

This repo also ships everything needed to showcase the platform publicly:

- **`auth-service/src/main/resources/static/`** — an interactive **live demo page** served
  same-origin by the service (so WebAuthn passkeys work without cross-origin friction). It walks a
  visitor through register → password login → passkey register → passkey login → an authenticated
  call, showing the real request/response and decoding the JWT at each step.
- **A per-IP rate limiter** (`com.authplatform.auth.ratelimit`) — off by default so local dev and
  tests are unaffected; enable it for a public deployment with
  `AUTH_PLATFORM_RATELIMIT_ENABLED=true` (defaults to 5 actions per IP per 24h). It is a demo abuse
  guard, not a security control — see its javadoc.
- **`Dockerfile`** + **`deploy/`** — a container image and a complete single-host deployment
  kit: Docker Compose (service + Postgres + Caddy auto-HTTPS) and an env template. Written for
  **Oracle Cloud Always Free** ARM, with any small VPS (Netcup, Hetzner) as a drop-in alternative.
  See [`deploy/DEPLOY.md`](deploy/DEPLOY.md).

> To exercise the built-in demo page **locally**, set `AUTH_PLATFORM_WEBAUTHN_ORIGIN=http://localhost:8080`
> (the page is served from `:8080`, whereas the default origin targets the `:3000` manual-test flow
> described later). Password register/login work regardless of that setting.

## Prerequisites

- **Java 21.**
- **Gradle 8.13** — you don't need it installed; the wrapper (`./gradlew`) is committed and pins
  this version.
- **Docker**, running, for Postgres (local dev) and for the Testcontainers-backed integration
  tests (they start a real `postgres:16-alpine` container per test class).

## Running locally

1. Start Postgres: `docker compose up -d`
2. Generate a key-protection secret and export it as an environment variable — **the app will
   not start without this**:
   ```bash
   export AUTH_PLATFORM_ISSUER_KEY_PROTECTION_SECRET=$(openssl rand -base64 32)
   ```
   This is the single most likely first-run stumble. `auth-service/src/main/resources/application.yml`
   binds `auth-platform.issuer.key-protection-secret` to
   `${AUTH_PLATFORM_ISSUER_KEY_PROTECTION_SECRET:}` — an intentionally empty default. If the
   environment variable is unset, blank, not valid base64, or does not decode to exactly 32 bytes,
   `KeyProtector`'s constructor throws and startup fails immediately with an actionable message,
   rather than silently falling back to a value that would otherwise have to live in source
   control. This secret encrypts the RSA private signing keys at rest (see "Security posture"
   below) — do not commit a real value anywhere, and do not lose it, since it cannot be recovered
   and losing it makes every stored private key unusable.
3. `./gradlew :auth-service:bootRun`

The service listens on `http://localhost:8080` by default (`server.port` in `application.yml`).

### Endpoints

| Method | Path                        | Auth required | Purpose                                       |
|--------|-----------------------------|:--------------:|------------------------------------------------|
| POST   | `/auth/register`            | no             | Create a user (email + password); 201 on success |
| POST   | `/auth/login`               | no             | Password login; returns a `TokenResponse`       |
| POST   | `/auth/refresh`             | no             | Rotate an access/refresh token pair (refresh token in body) |
| POST   | `/passkey/register/init`    | **yes**         | Start WebAuthn registration for the caller       |
| POST   | `/passkey/register/complete`| **yes**         | Finish WebAuthn registration                     |
| POST   | `/passkey/login/init`       | no             | Start WebAuthn login (by email)                 |
| POST   | `/passkey/login/complete`   | no             | Finish WebAuthn login; returns a `TokenResponse` |
| GET    | `/passkey`                  | **yes**         | List the caller's own passkeys                   |
| DELETE | `/passkey/{credentialId}`   | **yes**         | Remove one of the caller's own passkeys          |
| GET    | `/.well-known/jwks.json`    | no             | Standard JWKS — every stored signing key (active and rotated-out), in RFC 7517 form |

"Auth required" means the request needs a valid `Authorization: Bearer <accessToken>` header;
these routes carry auth-jwt-lib's `@JwtTokenVerification` and are rejected with 401 by
`JwtAuthenticationInterceptor` before the controller method runs if the token is missing or
fails verification. The passkey login endpoints are deliberately unauthenticated — they are how
a caller obtains a token in the first place — and the JWKS endpoint is deliberately
unauthenticated too, since a verifier that itself needed a token to fetch the keys used to verify
tokens would be a bootstrapping deadlock.

## Using auth-jwt-lib from another service

auth-jwt-lib is published as a normal Maven artifact with the coordinates
**`com.authplatform:auth-jwt-lib:0.1.0`** (a binary jar plus a sources jar and a javadoc jar). There
is no public repository for it yet, so publish it to your own machine's local Maven repository
first, from this repo's root:

```bash
./gradlew :auth-jwt-lib:publishToMavenLocal
```

That writes `~/.m2/repository/com/authplatform/auth-jwt-lib/0.1.0/`. Then, in the consuming
service:

```kotlin
repositories {
    mavenLocal()   // where publishToMavenLocal put it; drop this once it is published somewhere shared
    mavenCentral()
}

dependencies {
    implementation("com.authplatform:auth-jwt-lib:0.1.0")
}
```

Maven:

```xml
<dependency>
  <groupId>com.authplatform</groupId>
  <artifactId>auth-jwt-lib</artifactId>
  <version>0.1.0</version>
</dependency>
```

> `implementation(project(":auth-jwt-lib"))` also works, but **only for modules inside this
> repository** — a project path resolves against this repo's own `settings.gradle.kts`, so anywhere
> else it fails with `Project with path ':auth-jwt-lib' could not be found`. Use the artifact
> coordinates above from outside.

The library depends only on what it actually compiles against (`spring-boot-autoconfigure`,
`spring-boot`, `spring-context`, `spring-core`, `slf4j-api`, and `nimbus-jose-jwt`). It does **not**
drag in `spring-boot-starter-web`, so it never puts an embedded Tomcat or a second SLF4J binding
onto your runtime classpath: the servlet container, the web stack (`spring-web`/`spring-webmvc`,
which the library treats as `compileOnly`), and the logging binding are all yours to choose. What it
needs from you is a servlet-based Spring Boot application — that is what
`@ConditionalOnWebApplication(SERVLET)` requires, and adding `spring-boot-starter-web` (or
`-jetty`/`-undertow`) is enough.

Configure it under `auth-platform.jwt`:

```yaml
auth-platform:
  jwt:
    jwks-uri: https://your-auth-service/.well-known/jwks.json
    expected-issuer: auth-service
    # optional — leave unset to skip audience enforcement entirely
    # expected-audience: auth-platform-client
```

`jwks-uri` and `expected-issuer` are required. If either is missing or blank, the library's
auto-configuration fails startup fast with a named error (`JwtAutoConfiguration`'s
`requireProperty`), e.g.:

```
missing required configuration property 'auth-platform.jwt.jwks-uri': auth-jwt-lib cannot verify
jwt tokens without it. set it in application.yml/application.properties.
```

`expected-audience` is optional; when it is unset the `aud` claim is not checked at all.

**`@EnableJwtAuthentication` is optional in a Spring Boot application.** auth-jwt-lib ships a
`META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports` entry, so JWT
enforcement auto-configures and is active as soon as the library is on the classpath of a
servlet-based Spring Boot app — with or without the annotation. It cannot be gated behind the
annotation or a property, on purpose: that would make it possible to ship a service with silently
disabled JWT enforcement. The annotation exists only for (a) a plain, non-Boot Spring application
with no auto-configuration mechanism, where it is the only way to import the configuration, and
(b) as a self-documenting marker for readers, even though it has no additional effect in a Boot
app. Both halves of that are pinned by tests: `JwtAutoConfigurationTest` asserts the imports file
itself names `com.authplatform.jwt.config.JwtAutoConfiguration` (so deleting or misspelling it fails
the build instead of silently disabling enforcement), and `EnableJwtAuthenticationTest` drives the
annotation in a hand-built, non-Boot `AnnotationConfigWebApplicationContext` and asserts that the
same context without the annotation gets no beans at all.

Protect an endpoint:

```java
@RestController
public class SomeController {
    @JwtTokenVerification
    @GetMapping("/protected")
    public String protectedEndpoint(HttpServletRequest request) {
        JwtClaims claims = (JwtClaims) request.getAttribute(JwtAuthenticationInterceptor.CLAIMS_ATTRIBUTE);
        return "hello " + claims.email();
    }
}
```

The interceptor only ever places **verified** claims onto the request attribute; a request that
fails verification never reaches the handler method at all.

### What `JwtClaims` gives you — and where it stops being generic

`JwtClaims` is a fixed record exposing exactly seven values and nothing else: `userId` (the `sub`
claim), `email`, `issuer`, `audience` (the first entry of `aud`, if any), `sessionId`, `issuedAt`, and
`expiresAt`. There is no map of arbitrary claims and no escape hatch — a claim not in that list is
not reachable through this type. The two non-registered claims it reads are **`email`** and
**`sess`** (mapped to `sessionId`); both are what auth-service's own `JwtIssuer` writes.

That matters if you point the library at a third-party issuer. Verification itself is fully generic —
signature (RS256 by `kid` against the published JWKS), issuer, audience, `exp`/`nbf` all work against
any standards-compliant issuer, including Keycloak or Auth0. But the **claims half is not yet
generic**: neither writes a `sess` claim, so `sessionId` will be `null`, and `email` depends on the
issuer being configured to include it in the access token (Keycloak and Auth0 both often put it only
in the ID token). Nothing fails — you just get `null` where you expected a value.

### `extractClaimsWithoutVerification` — read-only, never for authorization

`JwtVerificationService` also exposes `extractClaimsWithoutVerification(String token)`, which
parses a token's claims without checking its signature, issuer, audience, or expiry.

**Never use it to authorize a request or to decide whether a caller is who they claim to be.** It
exists only for cases like logging or diagnostics where you already know the token is trusted
(e.g. you just issued it yourself) and only want to read its contents cheaply. Anywhere a token
arrives from a caller over the network, use `verify(token)` and check `JwtVerificationResult.valid()`
instead — that is the only method that actually checks the signature.

## Manually verifying the passkey happy path

The automated test suite covers every code path this project owns (challenge issuance,
persistence, error handling, sign-count anti-replay) using webauthn4j's own validated ceremony
logic. It does not fabricate a real WebAuthn attestation/assertion by hand, since that requires an
actual authenticator (a real security key, or a browser's platform authenticator / virtual
authenticator via WebDriver). To manually confirm the true happy path end-to-end:

1. Build a small HTML page using `navigator.credentials.create()` / `.get()` against
   `/passkey/register/init` + `/complete` and `/passkey/login/init` + `/complete`,
   base64url-encoding the resulting `ArrayBuffer` fields before sending them as JSON.
2. Serve it from `http://localhost:3000`. This must match both `auth-platform.webauthn.origin`
   and the entry in `auth-platform.cors.allowed-origins` in `application.yml` — both are already
   set to `http://localhost:3000`, so the browser's origin check and CORS preflight both pass
   without further changes.
3. Register a passkey with a platform authenticator (Touch ID / Windows Hello) or a security key,
   then log in with it and confirm a `TokenResponse` comes back.

## Security posture

**Enforced :**

- RS256-only verification with an explicit algorithm check (`JwtVerificationServiceImpl` rejects
  any JWT whose header algorithm is not exactly `RS256`, per RFC 8725 §3.1 — it does not trust
  whatever the underlying JWS library happens to accept).
- JWKS key resolution strictly by `kid`, and only keys usable for signature verification are ever
  cached: `JwksClientImpl` discards any published key whose declared `use` isn't `sig`, whose
  `alg` isn't an RSA family algorithm, or whose RSA modulus is under 2048 bits.
- Issuer checked (`iss` must equal the configured `expected-issuer` exactly).
- Audience check, when configured (`expected-audience` unset means the `aud` claim is not
  enforced at all — an explicit, documented opt-in).
- `exp` and `nbf` honoured (a missing `exp`, an expired token, or a not-yet-valid `nbf` all fail
  verification).
- Refresh-token rotation with single-use enforced by a real row lock: redeeming a refresh token
  takes a `PESSIMISTIC_WRITE` lock (`SELECT ... FOR UPDATE`) inside a transaction, so concurrent
  redemption attempts of the same token serialise and exactly one can ever succeed.
- Refresh tokens are stored only as SHA-256 digests — the raw, replayable token value is never
  persisted anywhere.
- RSA private signing keys are AES-256-GCM encrypted at rest, using a secret that must be
  supplied via `AUTH_PLATFORM_ISSUER_KEY_PROTECTION_SECRET` and fails startup closed (not open)
  if it is missing, malformed, or the wrong length — see "Running locally" above.
- WebAuthn challenges are single-use: consuming a challenge deletes it inside its own committed
  transaction before the rest of the login/registration ceremony runs, so a failed attempt can
  never retry the same challenge.
- Sign-count anti-replay for passkeys: an authenticator whose reported signature counter fails to
  strictly increase versus the stored value is rejected as a possible cloned authenticator.
- BCrypt passwords are capped at BCrypt's real 72-**byte** limit, enforced explicitly against the
  UTF-8 byte length (not the UTF-16 char length `@Size` checks), since exceeding it would let two
  different passwords silently hash identically.
- Uniform failure responses: password login (`LoginServiceImpl`), refresh-token redemption
  (`TokenServiceImpl`), and **both** passkey-login steps all return the same status/message
  regardless of cause. `/passkey/login/init` cannot distinguish "no such email" from "that account
  has no passkeys", and every `/passkey/login/complete` rejection returns exactly
  `401 passkey authentication failed` whether the credential id is unknown, belongs to a different
  user than the challenge, carries malformed base64url, fails WebAuthn validation, has a regressed
  sign count, or the user row has since been deleted. So a caller cannot enumerate registered
  emails, cannot distinguish "wrong password" from "no such user", and cannot learn that an account
  was deleted. (`/passkey/login/complete` previously returned four distinct 401 messages, including
  `user no longer exists` and one that echoed webauthn4j's own exception text.)
- Malformed input is a clean 4xx, never a 500: both passkey ceremonies decode their base64url
  request fields inside the guarded region, so an unauthenticated caller sending a `signature` of
  `"###"` to `/passkey/login/complete` gets the same `401` as garbage-but-decodable CBOR (and a
  bad `attestationObject` gets the same `400` on the registration side) instead of a 500 with a
  full stack trace at ERROR level — which was also an unbounded ERROR-log flooding vector, since
  `/passkey/login/init` is public and hands out live challenges. Every
  `@JwtTokenVerification`-protected controller likewise resolves the caller through
  `VerifiedCaller.requireUserId`, so a signature-valid token with a non-numeric `sub` (legal per
  RFC 7519 §4.1.2) is a `401`, not a 500.
- No DTO that carries a credential logs it in full: `RegisterRequest`, `LoginRequest`,
  `RefreshRequest`, and `TokenResponse` all override `toString()` to mask their secret fields, so
  a future log statement or exception message that interpolates one of these types cannot leak a
  plaintext password or a live, replayable token. `RegisterRequest` and `LoginRequest` mask the
  **email** too, so `toString()` no longer contradicts this project's stated
  no-email-addresses-in-logs policy (the same policy that stops `GlobalExceptionHandler` logging
  the postgres detail message). The record accessors still return every field in full — only
  `toString()` is masked.

**Not enforced — known, honest gaps, not fixed by this task:**

- **Account existence is disclosed by two other endpoints.** The uniform-failure guarantee above
  covers the login paths only. `POST /auth/register` returns `409 email is already registered` for
  an address that exists and `201` for one that doesn't, so it is a direct
  "is this email registered?" oracle. And `POST /passkey/login/init` distinguishes
  *has passkeys* (`200`) from *no such email or no passkeys* (`401`) — the messages are uniform, but
  the **status code** is not, and a `200` goes further and discloses the account's
  `allowCredentialIds`, which is inherent to the WebAuthn ceremony (the browser needs them for
  `navigator.credentials.get()`).
- **No signing-key revocation path.** `CertificateEntity` has an `active` flag, but nothing in the
  codebase ever sets it to `false`, and `GET /.well-known/jwks.json` publishes every stored key
  (active and rotated-out) by design. On the consumer side, `JwksClientImpl` caches a `kid`
  indefinitely once it has been seen and only refetches on a *miss*, so removing a key from the JWKS
  document does not untrust it: a leaked private key stays trusted by every already-running consumer
  until that process restarts. Revocation  means rotating the key **and** restarting consumers.
- **Authorization is default-open.** `SecurityConfig` ends in `anyRequest().permitAll()`; the only
  thing protecting an endpoint is auth-jwt-lib's `@JwtTokenVerification` on the controller or its
  method. A new controller that forgets the annotation is silently public, with nothing — no test, no
  filter, no convention check — failing because of it. There is also no role/scope model at all:
  `@JwtTokenVerification` answers "is this a valid token?", never "may this caller do this?".
- No rate limiting or account lockout on password login or passkey login. This is called out
  explicitly in `PasskeyLoginFlowServiceImpl`'s own javadoc as a pre-existing, cross-cutting gap.
- No refresh-token-reuse *family* revocation: redeeming an already-revoked refresh token is
  rejected, but doing so does not currently revoke the rest of that session's token history the
  way a full reuse-detection scheme would.
- A login timing side-channel: `LoginServiceImpl` returns immediately (no password hashing) when
  the email is unknown, but runs a full BCrypt comparison when the email exists and the password
  is wrong — the resulting response-time difference can be used to test whether an email is
  registered, independent of the uniform error *message* both paths already share.
- No background job purges expired, never-consumed WebAuthn challenges; an issued challenge that
  is never redeemed stays in the database past its 5-minute TTL until something attempts to
  consume it.
- Passkeys whose authenticator reports a signature counter of exactly `0` (common for
  synced/platform passkeys) get no counter-based replay protection at all — this is a
  spec-conformant WebAuthn behaviour (a `0` counter means "this authenticator doesn't implement
  one"), not a bug, but it does mean the single-use challenge is the only replay defence for
  those authenticators.

## Testing

```bash
./gradlew build                                                  # everything, both modules
./gradlew :auth-jwt-lib:test                                      # library unit tests only
./gradlew :auth-service:test                                      # service tests only
./gradlew :auth-service:test --tests "com.authplatform.auth.JwtLibInteropTest"  # the cross-module proof
```

Most `auth-service` tests are Testcontainers-backed (`@Testcontainers` + a real
`postgres:16-alpine` container per test class), so Docker must be running. `JwtLibInteropTest`
additionally binds a real embedded Tomcat on a random port and drives it over real HTTP.

## Troubleshooting

- **`PKIX path building failed` / `SSLHandshakeException` during a Gradle build.** This is
  expected behind a TLS-intercepting proxy: the JDK's own `cacerts` truststore doesn't trust the
  intercepted certificate chain the way the OS trust store does. The root `gradle.properties` sets
  `org.gradle.jvmargs=-Djavax.net.ssl.trustStoreType=Windows-ROOT` so the JVM reads the OS trust
  store (which also carries the public CAs); on macOS use `KeychainStore` instead. If you still hit
  this error, confirm that line matches your OS and run `./gradlew --stop` before retrying. Never
  disable TLS verification or switch a dependency repository to plain `http` to work around this.
- **Testcontainers fails with `Could not find a valid Docker environment` / an HTTP `400` from the
  daemon.** Modern Docker engines reject API versions below their advertised `MinAPIVersion`
  (Engine 29.x requires 1.40). The `auth-service` test task pins the client to a supported version
  via `systemProperty("api.version", "1.44")`; keep that in place if you see this on a newer engine.
- **App won't start: complains about `key-protection-secret`.** See step 2 under "Running
  locally" — export `AUTH_PLATFORM_ISSUER_KEY_PROTECTION_SECRET` before starting the app.
- **Tests hang or fail with a Docker/Testcontainers connection error.** Make sure Docker is
  running; most tests in `auth-service` need it to start a real Postgres container.
- **`missing required configuration property 'auth-platform.jwt.jwks-uri'` (or
  `expected-issuer`) at startup.** A consuming service is missing that key under
  `auth-platform.jwt` in its own configuration — see "Using auth-jwt-lib from another service"
  above.
