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
docker compose -f deploy/docker-compose.yml --env-file .env up -d --build
```

The first build compiles the Gradle project inside the image and takes several minutes on 2 ARM
OCPUs — that is normal. Caddy then requests the certificate on the first request to the domain.

```bash
docker compose -f deploy/docker-compose.yml --env-file .env logs -f auth-service
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
docker compose -f deploy/docker-compose.yml --env-file .env logs -f auth-service
```

Deploy an update:

```bash
git pull && docker compose -f deploy/docker-compose.yml --env-file .env up -d --build
```

Back up the database — the signing keys live there, encrypted:

```bash
docker compose -f deploy/docker-compose.yml --env-file .env exec postgres pg_dump -U authplatform authplatform > backup.sql
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
