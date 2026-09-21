#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SIGNATURE_DIR="${ROOT}/artifacts/release/signatures"
OUTPUT="${ROOT}/artifacts/readiness/signature-verification-results.json"
mkdir -p "$(dirname "${OUTPUT}")"
bundles=0
if [[ -d "${SIGNATURE_DIR}" ]]; then
  bundles="$(find "${SIGNATURE_DIR}" -type f -name '*.sigstore.json' | wc -l | tr -d ' ')"
fi
jq -n --argjson bundles "${bundles}" \
  '{status:(if $bundles > 0 then "requires_verification" else "blocked" end),sigstore_bundles:$bundles,
    certificate_identity:"GitHub protected release workflow",certificate_oidc_issuer:"https://token.actions.githubusercontent.com",
    reason:(if $bundles > 0 then "Run verification in the release workflow and retain its immutable evidence." else "No release signatures exist because the gate is closed." end)}' > "${OUTPUT}"
echo "${OUTPUT}"
exit 2
