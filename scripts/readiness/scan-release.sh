#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTPUT="${ROOT}/artifacts/release/scans"
SUMMARY="${ROOT}/artifacts/readiness/vulnerability-results.json"
mkdir -p "${OUTPUT}"
export DOCKER_HOST="${DOCKER_HOST:-$(docker context inspect --format '{{.Endpoints.docker.Host}}')}"

trivy fs --quiet --format json --output "${OUTPUT}/filesystem.json" \
  --scanners vuln,misconfig,secret --severity HIGH,CRITICAL \
  --skip-dirs .git --skip-dirs .venv --skip-dirs node_modules \
  --skip-dirs apps/web/node_modules --skip-dirs apps/web/.next \
  --skip-dirs infrastructure/readiness/runtime --skip-dirs artifacts \
  "${ROOT}"
trivy image --quiet --format json --output "${OUTPUT}/api-image.json" \
  --scanners vuln,secret --severity HIGH,CRITICAL cyberaudit-readiness-api:latest
trivy image --quiet --format json --output "${OUTPUT}/web-image.json" \
  --scanners vuln,secret --severity HIGH,CRITICAL cyberaudit-readiness-web:latest
trivy image --quiet --format json --output "${OUTPUT}/worker-image.json" \
  --scanners vuln,secret --severity HIGH,CRITICAL cyberaudit-readiness-worker:latest
trivy config --quiet --format json --output "${OUTPUT}/infrastructure.json" \
  --severity HIGH,CRITICAL "${ROOT}/infrastructure"

high="$(jq -s '[.[].Results[]? | .Vulnerabilities[]?, .Misconfigurations[]? | select(.Severity == "HIGH")] | length' "${OUTPUT}"/*.json)"
critical="$(jq -s '[.[].Results[]? | .Vulnerabilities[]?, .Misconfigurations[]? | select(.Severity == "CRITICAL")] | length' "${OUTPUT}"/*.json)"
secrets="$(jq -s '[.[].Results[]? | .Secrets[]?] | length' "${OUTPUT}"/*.json)"
status=passed
if (( high > 0 || critical > 0 || secrets > 0 )); then
  status=failed
fi
jq -n \
  --arg status "${status}" \
  --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg trivy_version "$(trivy --version | head -1)" \
  --argjson high "${high}" \
  --argjson critical "${critical}" \
  --argjson secrets "${secrets}" \
  '{status:$status,generated_at:$generated_at,trivy_version:$trivy_version,high:$high,critical:$critical,secrets:$secrets,risk_acceptance:"docs/security/readiness-risk-acceptance.json",reports:["artifacts/release/scans/filesystem.json","artifacts/release/scans/api-image.json","artifacts/release/scans/web-image.json","artifacts/release/scans/worker-image.json","artifacts/release/scans/infrastructure.json"]}' \
  > "${SUMMARY}"
echo "${SUMMARY}"
[[ "${status}" == passed ]]
