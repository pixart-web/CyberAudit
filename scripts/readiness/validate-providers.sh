#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
READINESS_DIR="${ROOT}/infrastructure/readiness"
RUNTIME="${READINESS_DIR}/runtime"
OUTPUT="${ROOT}/artifacts/readiness/provider-results.json"
COMPOSE=(docker-compose --env-file "${RUNTIME}/readiness.env" -f "${READINESS_DIR}/compose.production-like.yml")

mkdir -p "$(dirname "${OUTPUT}")"
"${ROOT}/scripts/readiness/generate-runtime.sh" >/dev/null
"${COMPOSE[@]}" build api
"${COMPOSE[@]}" up -d api worker
"${COMPOSE[@]}" exec -T api python -m cyberaudit.readiness_validation \
  | jq -e '
      select(
        .status == "passed"
        and .synthetic_data_only == true
        and .vault.resolved_nonempty == true
        and .object_storage.tenant_prefix == true
        and .object_storage.checksum_verified == true
        and .object_storage.deleted_after_validation == true
      )
    ' > "${OUTPUT}"
echo "${OUTPUT}"
