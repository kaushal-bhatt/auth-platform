# Deploying the live demo on AWS — Free Tier

This guides you through putting **auth-service** (the live demo, with the passkey UI it serves) on
AWS using the **12-month Free Tier**, and your **portfolio** on free static hosting. Everything is
env-var driven — no secrets are baked into the image.

> **Cost reality (honest):** on the Free Tier for the first 12 months this is roughly **$0–5/mo**
> (a `t3.micro` EC2 instance at 750 free hrs/mo + an `db.t3.micro` RDS instance at 750 free hrs/mo +
> 20 GB storage). After the 12 months it's about **$25–35/mo**. The single biggest saving is that
> this design uses **no Application Load Balancer** (that alone is ~$18/mo) — Caddy on the instance
> terminates TLS instead. A NAT gateway (~$32/mo) is likewise avoided by using a public subnet.

---

## The architecture

```
Visitor ──HTTPS──▶  Caddy (:443, auto Let's Encrypt)  ──▶  auth-service (:8080)  ──▶  RDS PostgreSQL
                    │  runs on one EC2 t3.micro (public subnet, Elastic IP)          (db.t3.micro, free tier)
Portfolio (static) ─┘  hosted free on Netlify/Vercel/Cloudflare/GitHub Pages
```

- **Passkeys work** because the demo page is served *by* auth-service at `auth.yourdomain.com`, so
  the page origin equals the WebAuthn relying-party origin. No cross-origin passkey headaches.
- **TLS** is mandatory for WebAuthn; Caddy provisions and renews a real certificate automatically.

---

## Two ways to run it — pick one

You chose **ECS-on-EC2**, so that's **Option B** below. But **Option A (plain Docker Compose on the
same EC2 instance)** is genuinely simpler, uses less of the tiny instance's RAM, and is what I'd
recommend for a free-tier demo. Both use the *same image and the same env vars*, so nothing is
wasted — you can switch later.

### ⚠️ The 1 GB RAM constraint (read this first)

A free-tier `t3.micro` has **1 GB RAM**. A JVM Spring Boot app + the ECS agent + Caddy is tight.
Two things make it comfortable:

1. **Use RDS for Postgres** (below) so the database is *not* on the instance.
2. **Add 2 GB of swap** on the instance:
   ```bash
   sudo dd if=/dev/zero of=/swapfile bs=1M count=2048
   sudo chmod 600 /swapfile && sudo mkswap /swapfile && sudo swapon /swapfile
   echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
   ```

---

## Step 1 — Database: RDS PostgreSQL (free tier)

1. RDS → Create database → **PostgreSQL** → **Free tier** template.
2. Instance: `db.t3.micro`, 20 GB gp3, **Public access: No**.
3. Set DB name `authplatform`, master user `authplatform`, and a strong password.
4. Put it in the **same VPC** as your EC2 instance. Edit its security group to allow inbound
   **5432 from the EC2 instance's security group** only.
5. Note the endpoint → that's your `SPRING_DATASOURCE_URL` host. The service runs Liquibase
   migrations on first boot, so the schema is created for you.

## Step 2 — A domain and DNS

You have a custom domain. Create an **A record**:

```
auth.yourdomain.com  →  <the Elastic IP you allocate in Step 3>
```

(Allocate the Elastic IP first if you like, or come back and set this once you have it. TLS issuance
in Step 5 needs this record to resolve.)

## Step 3 — EC2 instance

1. Allocate an **Elastic IP** (free while attached to a running instance).
2. Launch an EC2 instance: **Amazon Linux 2023**, `t3.micro`, in a **public subnet** with
   auto-assign public IP, then associate the Elastic IP.
3. **Security group inbound:** `22` (your IP only), `80` (0.0.0.0/0), `443` (0.0.0.0/0).
4. SSH in and install Docker + the swap from the warning box above:
   ```bash
   sudo dnf update -y && sudo dnf install -y docker git
   sudo systemctl enable --now docker
   sudo usermod -aG docker ec2-user   # re-login after this
   ```

---

## Option A — Docker Compose (recommended, simplest)

On the instance:

```bash
git clone https://github.com/YOUR_USERNAME/auth-platform.git
cd auth-platform
cp deploy/.env.example .env
# edit .env: AUTH_DOMAIN, ACME_EMAIL, the KEY_PROTECTION_SECRET (openssl rand -base64 32),
# SPRING_DATASOURCE_URL/USERNAME/PASSWORD (your RDS), and the WEBAUTHN_* values.
nano .env

docker compose -f deploy/docker-compose.aws.yml --env-file .env up -d --build
```

Caddy fetches a certificate for `AUTH_DOMAIN` within a minute (DNS must already point at the
instance). Visit `https://auth.yourdomain.com` — the demo page loads. Done.

Logs / restart:
```bash
docker compose -f deploy/docker-compose.aws.yml logs -f auth-service
docker compose -f deploy/docker-compose.aws.yml restart
```

---

## Option B — ECS-on-EC2 (the path you picked)

This registers the instance into an ECS cluster and runs the two containers as an ECS **task**.

1. **Push the image to ECR**
   ```bash
   aws ecr create-repository --repository-name auth-service
   aws ecr get-login-password --region REGION | docker login --username AWS \
     --password-stdin ACCOUNT_ID.dkr.ecr.REGION.amazonaws.com
   docker build -t auth-service .
   docker tag auth-service:latest ACCOUNT_ID.dkr.ecr.REGION.amazonaws.com/auth-service:latest
   docker push ACCOUNT_ID.dkr.ecr.REGION.amazonaws.com/auth-service:latest
   ```

2. **Store secrets in SSM Parameter Store** (free, and referenced by the task's `secrets` block):
   ```bash
   aws ssm put-parameter --name /auth-service/key-protection-secret --type SecureString \
     --value "$(openssl rand -base64 32)"
   aws ssm put-parameter --name /auth-service/db-password --type SecureString --value 'YOUR_DB_PASSWORD'
   ```

3. **Create the cluster and register the instance.** Create an ECS cluster (EC2 type), or launch the
   `t3.micro` with the ECS-optimized AMI and this user-data so it joins the cluster:
   ```bash
   #!/bin/bash
   echo "ECS_CLUSTER=auth-cluster" >> /etc/ecs/ecs.config
   ```
   Give the instance the `ecsInstanceRole`. Then place the Caddy config on the host (the task
   bind-mounts it):
   ```bash
   sudo mkdir -p /opt/auth/caddy-data
   sudo cp deploy/Caddyfile /opt/auth/Caddyfile
   ```

4. **Create the log group and register the task**
   ```bash
   aws logs create-log-group --log-group-name /ecs/auth-service
   # edit deploy/ecs-task-definition.json: replace ACCOUNT_ID, REGION, the RDS endpoint,
   # and every yourdomain.com value first.
   aws ecs register-task-definition --cli-input-json file://deploy/ecs-task-definition.json
   ```
   The task's execution role needs `AmazonECSTaskExecutionRolePolicy` **plus** permission to read
   those two SSM parameters (`ssm:GetParameters`).

5. **Run it as a service**
   ```bash
   aws ecs create-service --cluster auth-cluster --service-name auth-service \
     --task-definition auth-service --desired-count 1 --launch-type EC2
   ```
   Caddy binds host ports 80/443 and issues the certificate. Visit `https://auth.yourdomain.com`.

---

## Step 6 — Host the portfolio (free, always-on)

The `portfolio/` folder is plain static files — host it anywhere free:

- **Netlify / Cloudflare Pages / Vercel:** drag-and-drop the `portfolio/` folder, or connect the
  repo and set the publish directory to `portfolio`.
- **GitHub Pages:** push `portfolio/` to a repo and enable Pages.

Point your apex domain (`yourdomain.com`) at that host, and `auth.yourdomain.com` at the EC2 Elastic
IP. Then edit **`portfolio/script.js`** → set `CONFIG.demoUrl` to `https://auth.yourdomain.com` and
your `githubUrl` / `linkedinUrl` / `resumeUrl`.

---

## Verify end-to-end

```bash
curl https://auth.yourdomain.com/health                     # {"status":"UP"}
curl https://auth.yourdomain.com/.well-known/jwks.json      # your public keys
```

Then open the demo page and run all five steps — including registering and logging in with a
passkey. On the 6th action within 24h from the same IP you should get a friendly `429`, confirming
the rate limit is live.

## Keeping it cheap / turning it off

- Stop the EC2 instance when you don't need the demo up (you keep the Elastic IP association cost
  minimal; a *running* instance with an attached EIP is free, an *unattached* EIP is billed).
- Watch **Billing → Free Tier** in the console to stay ahead of the 750-hour limits.
- After 12 months, consider the free stack (Render/Koyeb + Neon) instead — the same image runs there.
