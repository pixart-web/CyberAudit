#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RAW="${ROOT}/artifacts/readiness/backend-coverage.json"
OUTPUT="${ROOT}/artifacts/readiness/coverage-results.json"
cd "${ROOT}"

if [[ ! -s .coverage ]]; then
  echo "No backend coverage database exists; run the full backend suite first." >&2
  exit 2
fi
.venv/bin/coverage json -o "${RAW}"
percent="$(jq -r '.totals.percent_covered' "${RAW}")"
status="failed"
if awk -v value="${percent}" 'BEGIN { exit !(value >= 75) }'; then status="passed"; fi
jq -n --arg status "${status}" --arg executed_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --argjson backend_percent "${percent}" \
  '{status:$status,executed_at:$executed_at,backend_percent:$backend_percent,
    backend_minimum:75,frontend_coverage:"not configured as a release threshold",
    source:"full pytest coverage database"}' > "${OUTPUT}"
echo "${OUTPUT}"
[[ "${status}" == "passed" ]]
