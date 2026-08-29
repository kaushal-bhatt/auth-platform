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

# The whole stack, not just this one service. Compose is declarative: it only
# recreates containers whose image or configuration actually changed, so the
# database and Caddy are still left alone on an ordinary rollout. Naming a single
# service looked safer but silently skipped changes to the others — a Caddy
# volume and command change sat unapplied through two deploys because nothing
# ever asked compose to converge that container.
echo "==> Converging the stack (${SERVICE} is the one being rolled out)"
"${COMPOSE[@]}" up -d

# A change to the Caddyfile alone does not alter Caddy's compose configuration,
# so the converge above leaves it running with the previous routing. Reload
# applies the new file with no downtime and without re-requesting certificates.
# It runs BEFORE the health check because that check goes through Caddy.
#
# The path must match the `command:` in docker-compose.yml — the config lives
# under the mounted directory, not at Caddy's default /etc/caddy/Caddyfile.
if "${COMPOSE[@]}" ps --status running --services 2>/dev/null | grep -qx caddy; then
    echo "==> Reloading Caddy"
    "${COMPOSE[@]}" exec -T caddy caddy reload --config /etc/caddy/conf/Caddyfile
fi

# A container that starts and then crash-loops must fail the pipeline, so wait
# for a real response through Caddy instead of trusting `up -d` returning 0.
echo "==> Waiting for https://${DOMAIN}${HEALTH_PATH}"
healthy=0
for attempt in $(seq 1 40); do
    # Insist on a 200, rather than trusting `curl -f`: curl does not treat a 3xx
    # as a failure, so a stale proxy config that redirects the request elsewhere
    # would report a perfectly healthy rollout of a service nobody can reach.
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "https://${DOMAIN}${HEALTH_PATH}" || echo 000)"
    if [ "$code" = "200" ]; then
        echo "==> Healthy after ${attempt} attempt(s)."
        healthy=1
        break
    fi
    sleep 3
done

if [ "$healthy" -ne 1 ]; then
    echo "!!! ${SERVICE} not healthy after ~2 minutes (last status: ${code}). Last 60 log lines:" >&2
    "${COMPOSE[@]}" logs --tail=60 "$SERVICE" >&2 || true
    exit 1
fi

# The box has a small disk and every deploy leaves the previous image behind.
# Only untagged (dangling) images go - the previous release keeps its sha tag so
# a rollback does not have to re-download it.
docker image prune -f >/dev/null 2>&1 || true

echo "==> Deployed ${IMAGE}:${TAG}"
