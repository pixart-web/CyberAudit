#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
READINESS_DIR="${ROOT}/infrastructure/readiness"
RUNTIME="${READINESS_DIR}/runtime"
OUTPUT="${ROOT}/artifacts/readiness/rls-results.json"
COMPOSE=(docker-compose --env-file "${RUNTIME}/readiness.env" -f "${READINESS_DIR}/compose.production-like.yml")

mkdir -p "$(dirname "${OUTPUT}")"
result="$("${COMPOSE[@]}" exec -T postgres psql -X -A -t -v ON_ERROR_STOP=1 \
  -U cyberaudit_migration -d cyberaudit \
  -f - < "${READINESS_DIR}/postgres/rls-validation.sql")"
printf '%s\n' "${result}" | sed -n '/^{/p' | jq -e 'select(
  .status == "passed"
  and .missing_context_assets == 0
  and .own_assets > 0
  and .foreign_assets == 0
  and .foreign_join_rows == 0
  and .foreign_subquery_rows == 0
  and .own_insert_rows == 1
  and .foreign_delete_rows == 0
  and .tenant_tables_without_rls == 0
  and .tenant_tables_without_runtime_policy == 0
  and .runtime_user_bypassrls == false
  and .runtime_user_superuser == false
)' > "${OUTPUT}"
echo "${OUTPUT}"
