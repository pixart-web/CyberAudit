#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
READINESS_DIR="${ROOT}/infrastructure/readiness"
RUNTIME="${READINESS_DIR}/runtime"
OUTPUT="${ROOT}/artifacts/readiness/dlq-results.json"
COMPOSE=(docker-compose --env-file "${RUNTIME}/readiness.env" -f "${READINESS_DIR}/compose.production-like.yml")

organization_id="$("${COMPOSE[@]}" exec -T postgres psql -X -A -t \
  -U cyberaudit_migration -d cyberaudit \
  -c "SELECT id FROM organizations WHERE slug='cyberaudit-demo'")"
[[ "${organization_id}" =~ ^[a-f0-9-]{36}$ ]]
"${COMPOSE[@]}" build api worker >/dev/null
"${COMPOSE[@]}" up -d api worker >/dev/null
"${COMPOSE[@]}" exec -T api python -m cyberaudit.readiness_dlq_validation "${organization_id}" \
  | jq -e 'select(
      .status == "passed"
      and .duplicate_deduplicated == true
      and .replay_completed == true
      and .discard_completed == true
      and .old_schema_replay_denied == true
      and .secrets_absent == true
      and .tenant_scoped == true
    )' > "${OUTPUT}"
echo "${OUTPUT}"
