#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTPUT_DIR="${ROOT}/artifacts/release/provenance"
OUTPUT="${OUTPUT_DIR}/local-build-provenance.json"
SUMMARY="${ROOT}/artifacts/readiness/provenance-results.json"
mkdir -p "${OUTPUT_DIR}"
cd "${ROOT}"

commit="$(git -C "${ROOT}" rev-parse HEAD)"
branch="$(git -C "${ROOT}" branch --show-current)"
dirty=false
if [[ -n "$(git -C "${ROOT}" status --porcelain)" ]]; then dirty=true; fi
artifact_hashes='[]'
if [[ -d artifacts/release/sbom ]]; then
  artifact_hashes="$(find artifacts/release/sbom -type f -print0 | sort -z | xargs -0 shasum -a 256 | jq -R -s 'split("\n") | map(select(length > 0) | capture("^(?<sha256>[a-f0-9]{64})  (?<path>.+)$"))')"
fi
jq -n \
  --arg commit "${commit}" --arg branch "${branch}" \
  --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg builder "local:cyberaudit-readiness-harness" \
  --argjson dirty "${dirty}" --argjson artifacts "${artifact_hashes}" \
  '{predicateType:"https://slsa.dev/provenance/v1",status:(if $dirty then "partial" else "generated" end),
    subject:$artifacts,buildDefinition:{externalParameters:{commit:$commit,branch:$branch},resolvedDependencies:[]},
    runDetails:{builder:{id:$builder},metadata:{invocationId:("local-" + $commit[0:12]),startedOn:$timestamp,finishedOn:$timestamp}},
    workflow_identity:null,working_tree_dirty:$dirty,
    notes:(if $dirty then "Local provenance is not releasable until the commit is frozen and CI identity attests it." else "Local provenance requires keyless CI attestation and human review." end)}' > "${OUTPUT}"
cp "${OUTPUT}" "${SUMMARY}"
echo "${OUTPUT}"
