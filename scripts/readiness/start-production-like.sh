#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
READINESS_DIR="${ROOT}/infrastructure/readiness"
RUNTIME="${READINESS_DIR}/runtime"
COMPOSE=(docker-compose --env-file "${RUNTIME}/readiness.env" -f "${READINESS_DIR}/compose.production-like.yml")

if ! docker info >/dev/null 2>&1; then
  echo "Docker is not functional. Start the approved local runtime first." >&2
  exit 1
fi

"${ROOT}/scripts/readiness/generate-runtime.sh"
set -a
# shellcheck disable=SC1090
source "${RUNTIME}/readiness.env"
set +a
"${COMPOSE[@]}" config --quiet
"${COMPOSE[@]}" up -d postgres redis vault minio keycloak
"${ROOT}/scripts/readiness/bootstrap-vault.sh"
"${ROOT}/scripts/readiness/bootstrap-minio.sh"
"${COMPOSE[@]}" up -d keycloak-proxy
"${COMPOSE[@]}" run --build --rm migrate
"${COMPOSE[@]}" run --rm --no-deps \
  -e ENVIRONMENT=development \
  -e DATABASE_RUNTIME_ROLE= \
  -e "DATABASE_URL=postgresql+asyncpg://cyberaudit_migration:${POSTGRES_PASSWORD}@postgres:5432/cyberaudit" \
  migrate python -m cyberaudit.seed
"${COMPOSE[@]}" run --rm --no-deps \
  -e ENVIRONMENT=development \
  -e DATABASE_RUNTIME_ROLE= \
  -e "DATABASE_URL=postgresql+asyncpg://cyberaudit_migration:${POSTGRES_PASSWORD}@postgres:5432/cyberaudit" \
  migrate python -m cyberaudit.seed_hardening
"${COMPOSE[@]}" run --rm --no-deps \
  -e ENVIRONMENT=development \
  -e DATABASE_RUNTIME_ROLE= \
  -e "DATABASE_URL=postgresql+asyncpg://cyberaudit_migration:${POSTGRES_PASSWORD}@postgres:5432/cyberaudit" \
  migrate python -m cyberaudit.seed_readiness

printf '%s\n' "ALTER ROLE cyberaudit_runtime LOGIN PASSWORD :'runtime_password';" | \
  "${COMPOSE[@]}" exec -T postgres psql -v ON_ERROR_STOP=1 \
  -U cyberaudit_migration -d cyberaudit \
  -v runtime_password="${CYBERAUDIT_RUNTIME_DB_PASSWORD}"

"${COMPOSE[@]}" up --build -d api worker web edge prometheus grafana otel
"${COMPOSE[@]}" ps
echo "Production-like edge: https://cyberaudit.localhost:18443"
echo "Keycloak: https://idp.localhost:18444"
