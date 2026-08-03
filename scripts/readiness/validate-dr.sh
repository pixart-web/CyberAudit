#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTPUT="${ROOT}/artifacts/readiness/dr-results.json"
RESTORE="${ROOT}/artifacts/readiness/restore-results.json"
mkdir -p "$(dirname "${OUTPUT}")"

restore_status="missing"
if [[ -s "${RESTORE}" ]]; then
  restore_status="$(jq -r '.status // "unknown"' "${RESTORE}")"
fi
jq -n \
  --arg executed_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg restore_status "${restore_status}" \
  '{status:"blocked",executed_at:$executed_at,isolated_restore_status:$restore_status,
    second_environment:false,endpoint_failover_executed:false,controlled_failback_executed:false,
    reason:"The isolated restore drill runs on the same Docker host and is not classified as disaster recovery.",
    required_action:"Run the documented drill on a second cluster or server and attach independently reviewed evidence."}' > "${OUTPUT}"
echo "${OUTPUT}"
exit 2
