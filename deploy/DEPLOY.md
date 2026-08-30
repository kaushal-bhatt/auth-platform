# Deploying the live demo — Oracle Cloud Always Free (or any small VPS)

This guides you through putting **auth-service** — and the interactive passkey demo page it serves
— on a public HTTPS domain, always on, for **$0/month**. Everything is env-var driven; no secrets
are baked into the image.

The target is an **Oracle Cloud Always Free** ARM instance, because "always free" there means
*permanently* free rather than a 12-month trial. Nothing in the deploy kit is Oracle-specific
though: it is plain Docker Compose, so **any VPS with at least 2 GB RAM** (Netcup, Hetzner, …) runs
the same three commands. See [Running on a plain VPS instead](#running-on-a-plain-vps-instead).

> **Cost reality (honest):** Oracle's Always Free ARM tier is $0 indefinitely, but it demands a
> credit card at signup for identity verification, and idle instances can be reclaimed (see
> [Keeping it alive](#keeping-it-alive)). A Netcup/Hetzner VPS costs roughly **€2–4/month** and has
> neither of those caveats. Both are far below the ~$25–35/month this would cost on AWS after its
> free tier, mostly because this design uses **no load balancer** — Caddy on the instance
> terminates TLS — and **no managed database** — Postgres runs as a container on the same host.

---

## The architecture

```
Visitor ──HTTPS──▶  Caddy (:443, auto Let's Encrypt)  ──▶  auth-service (:8080)  ──▶  Postgres
                    └──────────── all three as containers on ONE VM ─────────────────────┘
```

- **Passkeys work** because the demo page is served *by* auth-service at `auth.yourdomain.com`, so
  the page origin equals the WebAuthn relying-party origin. No cross-origin passkey headaches.
- **TLS is mandatory** for WebAuthn; Caddy provisions and renews a real certificate automatically.
- **Postgres is never published** — not to the host, not to the internet. Only the service reaches
  it, over the Compose network.

## What you need first

- A **domain** you control, so you can point `auth.yourdomain.com` at the instance. WebAuthn will
  not work on a bare IP — a real certificate on a real name is non-negotiable.
- An SSH keypair. Oracle asks for the public key while creating the instance.

---

## Step 1 — Create the Always Free instance

1. Sign up at [cloud.oracle.com](https://cloud.oracle.com). A payment method is required for
   verification even on Always Free; you are not charged as long as you stay on Always Free
   resources (the account stays in "Free Tier" until you explicitly upgrade).

2. ⚠️ **Your home region is permanent.** It is chosen at signup and cannot be changed afterwards.
   Targeting EU employers → pick **Frankfurt** or **Amsterdam**. Getting this wrong means a new
   account, not a setting change.

3. Compute → Instances → **Create instance**:
   - **Image:** Canonical Ubuntu 24.04 — the plain image, *not* "Minimal" (Minimal strips out
     packages this guide needs, `netfilter-persistent` among them). Oracle Linux 9 also works, but
     its firewall step differs — see Step 2.
   - **Shape:** change it to **Ampere / `VM.Standard.A1.Flex`** — the ARM shape is the one that is
     Always Free. The default x86 micro shape is much weaker.
   - **Size it 2 OCPU / 4 GB.** ⚠️ *Not* the full 4 OCPU / 24 GB, even though the free allocation
     allows it — see [Keeping it alive](#keeping-it-alive) for why a bigger instance is more likely
     to be reclaimed, not less.
   - **Networking:** assign a **public IPv4 address**.
   - Paste your **SSH public key**.

   > **"Out of host capacity"** on A1 shapes is common in popular regions. It is transient — retry
   > later, or try a different availability domain in the same region. It is not a problem with
   > your account.

4. Note the instance's **public IP**.

## Step 2 — Open ports 80 and 443 (two firewalls, both matter)

This is the single most common thing to get stuck on: Oracle instances sit behind **two**
independent firewalls, and traffic must be allowed through both.

**a) The VCN security list** (Oracle's network-level firewall):
Networking → Virtual Cloud Networks → your VCN → Security Lists → *Default Security List* →
**Add Ingress Rules**:

| Source CIDR | IP Protocol | Destination Port Range |
|---|---|---|
| `0.0.0.0/0` | TCP | `80` |
| `0.0.0.0/0` | TCP | `443` |

**b) The instance's own `iptables`.** Oracle's Ubuntu images ship with a restrictive ruleset that
allows only SSH. SSH in and add the rules, then persist them:

```bash
sudo iptables -I INPUT 6 -m state --state NEW -p tcp --dport 80 -j ACCEPT
```

```bash
sudo iptables -I INPUT 6 -m state --state NEW -p tcp --dport 443 -j ACCEPT
```

```bash
sudo netfilter-persistent save
```

On **Oracle Linux** use firewalld instead:

```bash
sudo firewall-cmd --permanent --add-service=http --add-service=https && sudo firewall-cmd --reload
```

## Step 3 — Point DNS at the instance

At your DNS provider, create an **A record**:

```
auth.yourdomain.com.   A   <the instance's public IP>
```

Wait until `dig +short auth.yourdomain.com` returns that IP before continuing. Caddy's certificate
request will fail if DNS has not propagated yet — recoverable, but confusing.

## Step 4 — Install Docker on the instance

```bash
sudo apt-get update && sudo apt-get install -y ca-certificates curl git && curl -fsSL https://get.docker.com | sudo sh && sudo usermod -aG docker $USER
```

Log out and back in for the group change to take effect.

Add swap. The build is the memory-hungry part, and swap costs nothing but disk:

```bash
sudo fallocate -l 2G /swapfile && sudo chmod 600 /swapfile && sudo mkswap /swapfile && sudo swapon /swapfile && echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
```

## Step 5 — Configure the environment

```bash
git clone https://github.com/kaushal-bhatt/auth-platform.git && cd auth-platform && cp deploy/.env.example .env
```

Generate the signing-key encryption secret and paste it into `.env`:

```bash
openssl rand -base64 32
```

Then edit `.env` and set, at minimum:

| Variable | Value |
|---|---|
| `AUTH_DOMAIN` | `auth.yourdomain.com` |
| `ACME_EMAIL` | your email (Let's Encrypt expiry notices) |
| `AUTH_PLATFORM_ISSUER_KEY_PROTECTION_SECRET` | the `openssl rand -base64 32` output |
| `POSTGRES_PASSWORD` **and** `SPRING_DATASOURCE_PASSWORD` | the same strong password |
| `AUTH_PLATFORM_WEBAUTHN_RELYING_PARTY_ID` | `auth.yourdomain.com` (no scheme) |
| `AUTH_PLATFORM_WEBAUTHN_ORIGIN` | `https://auth.yourdomain.com` |

⚠️ **Keep `AUTH_PLATFORM_ISSUER_KEY_PROTECTION_SECRET` safe and stable.** RSA signing keys are
AES-256-GCM encrypted at rest with it. Lose it and every stored key becomes unusable.

`.env` is gitignored. Never commit the real one.

## Step 6 — Build and run

```bash
docker compose -f deploy/docker-compose.yml --env-file .env --env-file .env.images up -d --build
```

The first build compiles the Gradle project inside the image and takes several minutes on 2 ARM
OCPUs — that is normal. Caddy then requests the certificate on the first request to the domain.

```bash
docker compose -f deploy/docker-compose.yml --env-file .env --env-file .env.images logs -f auth-service
```

## Step 7 — Verify end-to-end

```bash
curl https://auth.yourdomain.com/health
```

```bash
curl https://auth.yourdomain.com/.well-known/jwks.json
```

The first returns `{"status":"UP"}`, the second your public keys. Then open
`https://auth.yourdomain.com` in a browser and walk the demo: register → password login →
**passkey register** → **passkey login** → authenticated call. The passkey steps are the ones that
prove the TLS and relying-party configuration is right.

---

## Continuous deployment (GitHub Actions, self-hosted runner)

`.github/workflows/deploy.yml` turns a push to `main` into a rollout. The way the work is
split is what makes it quick:

| Where | What it does |
|---|---|
| **Self-hosted runner** (a development machine) | `gradlew build` (compile + tests), `docker build`, push the image to GHCR |
| **This server** | `docker pull`, restart, health-check — via `deploy/remote-deploy.sh` |

The server compiles nothing. A rollout is a pull of an image that already exists, so it
takes seconds rather than the several minutes a Gradle build costs on 2 vCPUs — and the
box is never pegged at 100% CPU while a visitor is using the demo.

Two consequences of the runner being self-hosted rather than GitHub-hosted:

- **Deploys only happen while that machine is on** with its runner service running. A push
  made while it is off stays queued until the runner comes back.
- The workflow deliberately has **no `pull_request` trigger**. This repository is public,
  and a `pull_request` trigger on a self-hosted runner lets anyone run arbitrary code on
  that machine by opening a PR. `push` to `main` requires write access.

### One-time setup

**1. Register the runner.** Repo → Settings → Actions → Runners → *New self-hosted runner*
→ Windows x64, and run the commands it prints. Then install it as a service so it survives
a reboot:

```powershell
.\svc.ps1 install <your-windows-username>
```

> ⚠️ Install it **as your own user account**, not the default `NETWORK SERVICE`. Docker
> Desktop publishes its engine on a *per-user* named pipe, so a runner service under
> `NETWORK SERVICE` cannot build images at all. Docker Desktop itself must also be running
> when a build starts — enable its *"Start Docker Desktop when you sign in"* setting.

**2. Create a deploy key.** It must have an **empty passphrase**; a pipeline cannot answer
a prompt. Generate it on the development machine, keeping it separate from your personal
SSH key so it can be revoked on its own:

```powershell
ssh-keygen -t ed25519 -N '""' -C "github-actions-deploy" -f "$env:USERPROFILE\.ssh\auth_platform_deploy"
```

Authorise the public half on the server:

```bash
cat >> ~/.ssh/authorized_keys
```

**3. Add four repository secrets** (Settings → Secrets and variables → Actions):

| Secret | Value |
|---|---|
| `DEPLOY_HOST` | the server's IP or hostname |
| `DEPLOY_USER` | the SSH user (`root`, unless you made another) |
| `DEPLOY_SSH_KEY` | the full **private** key, `-----BEGIN` through `-----END` |
| `DEPLOY_KNOWN_HOSTS` | output of `ssh-keyscan -t ed25519 <host>` |

`DEPLOY_KNOWN_HOSTS` is not optional bureaucracy: without it the deploy step either fails
on an unknown host key, or — if you disable the check — trusts whatever answers on that
address, which is exactly the MITM the check exists to prevent.

**4. Make the GHCR package public.** GitHub creates packages private even for public repos,
and the server pulls anonymously. After the first successful push: your GitHub profile →
Packages → `auth-service` → Package settings → Change visibility → Public. (Alternative: run
`docker login ghcr.io` on the server with a read-only token, and keep the package private.)

### Rolling back

Every deploy is tagged with its commit sha and the live one is recorded as `AUTH_IMAGE_TAG`
in the server's `.env`. To go back to an earlier build, on the server:

```bash
cd ~/auth-platform && bash deploy/remote-deploy.sh auth-service <older-commit-sha>
```

Nothing is rebuilt — that image is still in the registry.

## Adding the portfolio

The personal site runs on this same host, at the bare domain, sharing the Postgres container.
It lives in its own repository (`kaushal-portfolio`) with its own deploy workflow; this host
only pulls its image, exactly as it does for auth-service.

### Its own database and role

The site gets a **separate Postgres role and database**, not auth-platform's. It is the more
exposed of the two services, and a separate role means a flaw there cannot read the auth
tables. The Postgres volume already exists, so an `initdb` script would never run — create
them once by hand:

```bash
docker compose -f deploy/docker-compose.yml --env-file .env --env-file .env.images exec -T postgres psql -U "$POSTGRES_USER" -d postgres
```

```sql
CREATE ROLE portfolio LOGIN PASSWORD 'the-value-you-put-in-PORTFOLIO_DB_PASSWORD';
CREATE DATABASE portfolio OWNER portfolio;
```

### Schema and content

The image serves; it never migrates. That is deliberate — a container restart must not be
able to change the database schema on its own.

Postgres is **not published to the host** — it is `expose`d only, reachable from inside the
compose network and nowhere else. So this runs in a throwaway Node container attached to that
network, which also means the host needs no Node installed:

```bash
git clone https://github.com/kaushal-bhatt/kaushal-portfolio.git /tmp/portfolio
```

```bash
docker run --rm -v /tmp/portfolio:/app -w /app --network deploy_default -e DATABASE_URL="postgresql://portfolio:<password>@postgres:5432/portfolio" node:22-alpine sh -c "apk add --no-cache openssl && npm ci && npx prisma db push && npm run db:seed"
```

`postgres` is the compose service name, and `deploy_default` is the network compose creates
for this stack — it is named after the directory holding the compose file, not the project
folder. Check with `docker network ls` if it differs.

The seed is non-destructive: it skips any table that already has rows unless `SEED_FORCE=true`,
so re-running it cannot wipe the site. Delete `/tmp/portfolio` afterwards.

### Wiring it up

1. Set `ROOT_DOMAIN`, `PORTFOLIO_DB_PASSWORD`, and the SSO settings in `.env`:
   `AUTH_PLATFORM_SSO_CLIENT_SECRET`, `AUTH_PLATFORM_SSO_REDIRECT_URIS`,
   `AUTH_PLATFORM_SSO_REQUIRED_ROLE`. The secret is one variable read by both
   containers — auth-service verifies it, the site presents it.
2. Point both the apex and `www` at this host (A records, **DNS only** — a proxy in front
   breaks the ACME challenge).
3. `docker compose -f deploy/docker-compose.yml --env-file .env --env-file .env.images up -d`

Caddy serves the site at the apex and 301s `www` to it.

> A self-hosted runner belongs to **one repository** — GitHub only offers shared runners at
> organisation level, which a personal account does not have. So the portfolio needs a
> *second* runner registered from its own repo. Same machine, different folder.

### Granting the admin role

The portfolio's admin panel is reached through this service's SSO flow, and the client is
configured to require the role `portfolio-admin`. **Nothing grants it automatically.**
Registration on the demo is open to anyone, so a valid token means only "this person signed
up"; the role is what separates you from every visitor who tried the demo.

Grant it once, to your own account:

```bash
docker compose -f deploy/docker-compose.yml --env-file .env --env-file .env.images exec -T postgres psql -U "$POSTGRES_USER" -d "$POSTGRES_DB"
```

```sql
INSERT INTO auth.user_role (user_id, role)
SELECT id, 'portfolio-admin' FROM auth.app_user WHERE email = 'you@example.com';
```

It takes effect on the next token issued — access tokens are short-lived precisely so an
authorisation change does not wait for a session to end. Revoking is the matching `DELETE`.

> **One interaction to know about.** The SSO login goes through `/passkey/login/*`, which the
> rate limiter counts (30 requests per IP per 24h, about five demo runs). Signing in to your own
> admin panel therefore spends from the same budget as anyone demoing from your IP. It is
> unlikely to bite — you sign in rarely — but if it ever does, the fix is to count the SSO path
> separately rather than to loosen the demo's limit.

## Keeping it alive

Oracle reclaims **idle** Always Free compute instances. Its criteria are evaluated over a 7-day
window, and **all** of them must hold for reclamation:

- CPU utilisation below 20%, **and**
- network utilisation below 20%, **and**
- memory utilisation below 20%.

This is why Step 1 says **4 GB, not 24 GB**. On a 24 GB instance the JVM plus Postgres would sit
around 8% memory — inside the reclamation band. On 4 GB the same workload sits at roughly 40–50%,
which alone keeps the instance safe regardless of how quiet the traffic is.

Belt and braces: put a free [UptimeRobot](https://uptimerobot.com) monitor on
`https://auth.yourdomain.com/health` at a 5-minute interval. It keeps network utilisation off the
floor *and* emails you the moment a visitor would have found a dead link.

## Operating it

Follow the logs:

```bash
docker compose -f deploy/docker-compose.yml --env-file .env --env-file .env.images logs -f auth-service
```

Deploy an update by hand. Normally CI does this for you — see
[Continuous deployment](#continuous-deployment-github-actions-self-hosted-runner) — but the
same script is what you run to deploy or roll back manually:

```bash
git pull --ff-only && bash deploy/remote-deploy.sh auth-service <commit-sha-or-latest>
```

Back up the database — the signing keys live there, encrypted:

```bash
docker compose -f deploy/docker-compose.yml --env-file .env --env-file .env.images exec postgres pg_dump -U authplatform authplatform > backup.sql
```

## Running on a plain VPS instead

On Netcup, Hetzner, or anything similar, **Steps 1, 2 and 4 collapse into**: create the server with
Ubuntu, then install Docker exactly as in Step 4. There is no VCN security list and no pre-loaded
`iptables` ruleset to fight — though if the provider offers a cloud firewall, open 80 and 443 there.
Steps 3 and 5–7 are identical, and so is `docker-compose.yml`.

Pick **at least 2 GB RAM**. The Compose file caps auth-service at 1200 MB and Postgres at 512 MB,
which fits 2 GB with room for the OS; below that, raise the swap and lower the `mem_limit` values.

## Troubleshooting

| Symptom | Cause |
|---|---|
| Connection times out | Ingress open in only *one* of the two firewalls — recheck both halves of Step 2 |
| Caddy cannot get a certificate | DNS not propagated yet, or port 80 blocked (the ACME challenge needs it) |
| Passkey buttons error in the browser | `AUTH_PLATFORM_WEBAUTHN_ORIGIN` / `RELYING_PARTY_ID` do not match the URL you loaded |
| `auth-service` restarts in a loop | Wrong DB password — `POSTGRES_PASSWORD` and `SPRING_DATASOURCE_PASSWORD` must match |
| Build killed partway through | Out of memory during Gradle — add the swap file from Step 4 |
| "Out of host capacity" creating the instance | Transient A1 shortage in that region; retry or change availability domain |
