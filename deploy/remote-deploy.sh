#!/usr/bin/env bash
# =============================================================================
#  Runs ON THE SERVER. Invoked over SSH by .github/workflows/deploy.yml, after
#  that workflow has already built the image and pushed it to GHCR.
#
#      bash deploy/remote-deploy.sh <image-tag>
#
#  Nothing is compiled here - the tag names an image that already exists. Safe
#  to run by hand too, which is also how you roll back:
#
#      bash deploy/remote-deploy.sh <an-older-commit-sha>
# =============================================================================
set -euo pipefail

TAG="${1:?usage: remote-deploy.sh <image-tag>}"

# Must match the image: line in deploy/docker-compose.yml.
IMAGE="ghcr.io/kaushal-bhatt/auth-service"

cd "$(dirname "$0")/.." # repo root, where .env lives

COMPOSE=(docker compose -f deploy/docker-compose.yml --env-file .env)

# Read AUTH_DOMAIN rather than sourcing .env: the file holds passwords that
# would be word-split or glob-expanded by `source`.
AUTH_DOMAIN="$(sed -n 's/^AUTH_DOMAIN=//p' .env | head -1 | tr -d '"')"
if [ -z "$AUTH_DOMAIN" ]; then
    echo "AUTH_DOMAIN is not set in .env - cannot health-check the rollout." >&2
    exit 1
fi

echo "==> Pulling ${IMAGE}:${TAG}"
docker pull "${IMAGE}:${TAG}"

# Record which build is live. docker-compose.yml reads AUTH_IMAGE_TAG, so a
# plain `docker compose up -d` on this box later brings back the SAME image
# rather than silently drifting to whatever `latest` points at by then.
echo "==> Pinning AUTH_IMAGE_TAG=${TAG} in .env"
if grep -q '^AUTH_IMAGE_TAG=' .env; then
    sed -i "s|^AUTH_IMAGE_TAG=.*|AUTH_IMAGE_TAG=${TAG}|" .env
else
    printf '\n# Set by deploy/remote-deploy.sh - the image build currently deployed.\nAUTH_IMAGE_TAG=%s\n' "$TAG" >> .env
fi

echo "==> Starting containers"
"${COMPOSE[@]}" up -d

# A container that starts and then crash-loops must fail the pipeline, so wait
# for a real response through Caddy instead of trusting `up -d` returning 0.
echo "==> Waiting for https://${AUTH_DOMAIN}/health"
healthy=0
for attempt in $(seq 1 40); do
    if curl -fsS --max-time 5 -o /dev/null "https://${AUTH_DOMAIN}/health"; then
        echo "==> Healthy after ${attempt} attempt(s)."
        healthy=1
        break
    fi
    sleep 3
done

if [ "$healthy" -ne 1 ]; then
    echo "!!! Not healthy after ~2 minutes. Last 60 log lines:" >&2
    "${COMPOSE[@]}" logs --tail=60 auth-service >&2 || true
    exit 1
fi

# The box has a small disk and every deploy leaves the previous image behind.
# Only untagged (dangling) images go - the previous release keeps its sha tag
# so a rollback does not have to re-download it.
docker image prune -f >/dev/null 2>&1 || true

echo "==> Deployed ${IMAGE}:${TAG}"
