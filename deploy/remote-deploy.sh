#!/usr/bin/env bash
# =============================================================================
#  Runs ON THE SERVER. Invoked over SSH by the deploy workflow in whichever
#  repository just built an image, after that image is already in GHCR.
#
#      bash deploy/remote-deploy.sh <service> <image-tag>
#
#  <service> is `auth-service` or `portfolio`. Nothing is compiled here — the
#  tag names an image that already exists. Safe to run by hand, which is also
#  how you roll back:
#
#      bash deploy/remote-deploy.sh auth-service <an-older-commit-sha>
# =============================================================================
set -euo pipefail

SERVICE="${1:?usage: remote-deploy.sh <auth-service|portfolio> <image-tag>}"
TAG="${2:?usage: remote-deploy.sh <auth-service|portfolio> <image-tag>}"

cd "$(dirname "$0")/.." # repo root, where .env lives

# Per-service: the image to pull, the .env key that records the live build, and
# the hostname to health-check through Caddy once it restarts.
case "$SERVICE" in
    auth-service)
        IMAGE="ghcr.io/kaushal-bhatt/auth-service"
        TAG_VAR="AUTH_IMAGE_TAG"
        DOMAIN_VAR="AUTH_DOMAIN"
        HEALTH_PATH="/health"
        ;;
    portfolio)
        IMAGE="ghcr.io/kaushal-bhatt/portfolio"
        TAG_VAR="PORTFOLIO_IMAGE_TAG"
        DOMAIN_VAR="ROOT_DOMAIN"
        HEALTH_PATH="/"
        ;;
    *)
        echo "Unknown service '${SERVICE}' — expected auth-service or portfolio." >&2
        exit 1
        ;;
esac

COMPOSE=(docker compose -f deploy/docker-compose.yml --env-file .env)

# Read the domain rather than sourcing .env: that file holds passwords which
# `source` would word-split or glob-expand.
DOMAIN="$(sed -n "s/^${DOMAIN_VAR}=//p" .env | head -1 | tr -d '"')"
if [ -z "$DOMAIN" ]; then
    echo "${DOMAIN_VAR} is not set in .env - cannot health-check the rollout." >&2
    exit 1
fi

echo "==> Pulling ${IMAGE}:${TAG}"
docker pull "${IMAGE}:${TAG}"

# Record which build is live. docker-compose.yml reads this variable, so a plain
# `docker compose up -d` on this box later brings back the SAME image rather
# than silently drifting to whatever `latest` points at by then.
echo "==> Pinning ${TAG_VAR}=${TAG} in .env"
if grep -q "^${TAG_VAR}=" .env; then
    sed -i "s|^${TAG_VAR}=.*|${TAG_VAR}=${TAG}|" .env
else
    printf '\n# Set by deploy/remote-deploy.sh - the %s build currently deployed.\n%s=%s\n' \
        "$SERVICE" "$TAG_VAR" "$TAG" >> .env
fi

# Only this service is recreated. Postgres and Caddy keep running, so a deploy
# never restarts the database or drops the TLS certificates.
echo "==> Starting ${SERVICE}"
"${COMPOSE[@]}" up -d "$SERVICE"

# The Caddyfile is a bind mount, so the `git pull` above can have changed it
# without the running container noticing — and the line above only touches one
# app service. Reload applies the new routing with no downtime and without
# re-requesting certificates. It has to happen BEFORE the health check, because
# that check goes through Caddy.
if "${COMPOSE[@]}" ps --status running --services 2>/dev/null | grep -qx caddy; then
    echo "==> Reloading Caddy"
    "${COMPOSE[@]}" exec -T caddy caddy reload --config /etc/caddy/Caddyfile
else
    echo "==> Caddy is not running; bringing the whole stack up"
    "${COMPOSE[@]}" up -d
fi

# A container that starts and then crash-loops must fail the pipeline, so wait
# for a real response through Caddy instead of trusting `up -d` returning 0.
echo "==> Waiting for https://${DOMAIN}${HEALTH_PATH}"
healthy=0
for attempt in $(seq 1 40); do
    if curl -fsS --max-time 5 -o /dev/null "https://${DOMAIN}${HEALTH_PATH}"; then
        echo "==> Healthy after ${attempt} attempt(s)."
        healthy=1
        break
    fi
    sleep 3
done

if [ "$healthy" -ne 1 ]; then
    echo "!!! ${SERVICE} not healthy after ~2 minutes. Last 60 log lines:" >&2
    "${COMPOSE[@]}" logs --tail=60 "$SERVICE" >&2 || true
    exit 1
fi

# The box has a small disk and every deploy leaves the previous image behind.
# Only untagged (dangling) images go - the previous release keeps its sha tag so
# a rollback does not have to re-download it.
docker image prune -f >/dev/null 2>&1 || true

echo "==> Deployed ${IMAGE}:${TAG}"
