#!/usr/bin/env bash
# Safe evaluation deployment: preflight -> backup -> build -> migrate -> up -> smoke.
# Run ON the server from this directory, after reviewing the diff. Never auto-run from CI.
set -euo pipefail
cd "$(dirname "$0")"
if docker compose version >/dev/null 2>&1; then DC="docker compose"; else DC="docker-compose"; fi

SHA="${1:?usage: ./deploy.sh <git-sha-to-deploy> [repo-dir]}"
REPO="${2:-../..}"
[[ -f .env ]] || { echo "Missing .env (copy .env.example, chmod 600)"; exit 1; }
set -a; source .env; set +a
for v in POSTGRES_PASSWORD REDIS_PASSWORD JWT_SECRET ENCRYPTION_KEY CANONICAL_HOST; do
  [[ -n "${!v:-}" ]] || { echo "Refusing to deploy: $v is empty"; exit 1; }
done
[[ "${#JWT_SECRET}" -ge 32 && "${#ENCRYPTION_KEY}" -ge 32 ]] || { echo "JWT_SECRET/ENCRYPTION_KEY must be >=32 chars"; exit 1; }

FREE_KB=$(df -Pk . | awk 'NR==2{print $4}')
[[ "$FREE_KB" -gt 5000000 ]] || { echo "Less than ~5 GB free disk; aborting"; exit 1; }

mkdir -p backups releases
STAMP=$(date -u +%Y%m%dT%H%M%SZ)

# 1. Record what is running now (rollback target) -----------------------------------
$DC ps --format json > "releases/$STAMP.before.json" 2>/dev/null || true
echo "previous_api_image=$($DC images api -q 2>/dev/null | head -1)" > "releases/$STAMP.rollback.env" || true

# 2. Verified backup BEFORE any migration (only if a database already exists) --------
if $DC ps postgres --status running -q | grep -q .; then
  $DC exec -T postgres pg_dump -U cyberaudit -Fc cyberaudit > "backups/$STAMP.dump"
  $DC exec -T postgres pg_restore -l < "backups/$STAMP.dump" > /dev/null  # catalogue must parse
  sha256sum "backups/$STAMP.dump" > "backups/$STAMP.dump.sha256"
  echo "Backup OK: backups/$STAMP.dump"
else
  echo "No running database: first install, nothing to back up."
fi

# 3. Build immutable images from the exact commit ------------------------------------
git -C "$REPO" cat-file -e "$SHA^{commit}"
WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT
git -C "$REPO" archive "$SHA" | tar -x -C "$WORK"
export CYBERAUDIT_API_IMAGE="cyberaudit-api:$SHA"
export CYBERAUDIT_WEB_IMAGE="cyberaudit-web:$SHA"
docker build -f "$WORK/infrastructure/docker/api.Dockerfile" -t "$CYBERAUDIT_API_IMAGE" "$WORK"
docker build -f "$WORK/infrastructure/docker/web.Dockerfile" \
  --build-arg NEXT_PUBLIC_API_URL="https://$CANONICAL_HOST/api/v1" -t "$CYBERAUDIT_WEB_IMAGE" "$WORK"
echo "api_image=$CYBERAUDIT_API_IMAGE ($(docker image inspect -f '{{.Id}}' "$CYBERAUDIT_API_IMAGE"))" | tee "releases/$STAMP.after.txt"
echo "web_image=$CYBERAUDIT_WEB_IMAGE ($(docker image inspect -f '{{.Id}}' "$CYBERAUDIT_WEB_IMAGE"))" | tee -a "releases/$STAMP.after.txt"

# 4. Start (migrate runs as a one-shot dependency of api/worker) ---------------------
$DC up -d --remove-orphans
$DC wait migrate >/dev/null 2>&1 || true
$DC logs migrate | tail -5

# 5. Smoke test; on failure print rollback instructions (never auto-destroys data) ---
if ./smoke-test.sh "https://$CANONICAL_HOST"; then
  echo "DEPLOY OK: $SHA"
else
  echo "SMOKE FAILED. Rollback: set CYBERAUDIT_*_IMAGE in .env to the previous images in releases/$STAMP.rollback.env"
  echo "and run '$DC up -d'. Restore data ONLY from backups/$STAMP.dump after review (see RUNBOOK.md)."
  exit 1
fi
