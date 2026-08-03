#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTPUT="${ROOT}/artifacts/release/sbom"
SUMMARY="${ROOT}/artifacts/readiness/sbom-results.json"
mkdir -p "${OUTPUT}"
export DOCKER_HOST="${DOCKER_HOST:-$(docker context inspect --format '{{.Endpoints.docker.Host}}')}"

components=(api-source web-source api-image web-image worker-image runner-image)
sources=(
  "dir:${ROOT}/apps/api"
  "dir:${ROOT}/apps/web"
  "docker:cyberaudit-readiness-api:latest"
  "docker:cyberaudit-readiness-web:latest"
  "docker:cyberaudit-readiness-worker:latest"
  "docker:$(jq -r '.image' "${ROOT}/artifacts/readiness/docker-runner-results.json")"
)

artifacts=()
for index in "${!components[@]}"; do
  component="${components[$index]}"
  source="${sources[$index]}"
  cyclonedx="${OUTPUT}/${component}.cyclonedx.json"
  spdx="${OUTPUT}/${component}.spdx.json"
  rm -f "${cyclonedx}" "${spdx}"
  syft "${source}" -q -o "cyclonedx-json=${cyclonedx}" -o "spdx-json=${spdx}"
  artifacts+=("${cyclonedx}" "${spdx}")
done

files_json='[]'
for artifact in "${artifacts[@]}"; do
  relative="${artifact#${ROOT}/}"
  digest="$(shasum -a 256 "${artifact}" | awk '{print $1}')"
  size="$(stat -f '%z' "${artifact}")"
  files_json="$(jq -n --argjson files "${files_json}" --arg path "${relative}" --arg sha256 "${digest}" --argjson size_bytes "${size}" '$files + [{path:$path,sha256:$sha256,size_bytes:$size_bytes}]')"
done
jq -n \
  --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg syft_version "$(syft version | awk -F': ' '/Version:/ {print $2; exit}')" \
  --argjson files "${files_json}" \
  '{status:"partial",generated_at:$generated_at,formats:["CycloneDX JSON","SPDX JSON"],syft_version:$syft_version,files:$files,release_bundle_pending:true,notes:"Component SBOMs generated. Release bundle SBOM requires a frozen clean commit."}' \
  > "${SUMMARY}"
echo "${SUMMARY}"
