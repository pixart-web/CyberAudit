#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTPUT="${ROOT}/artifacts/readiness/oidc-browser-results.json"
EVIDENCE_DIR="${ROOT}/artifacts/readiness/oidc"
mkdir -p "${EVIDENCE_DIR}"

cat > "${OUTPUT}" <<EOF
{
  "status": "blocked",
  "provider": "Keycloak",
  "automated_browser_evidence": false,
  "reason": "The laboratory CA is not trusted by the managed browser. TLS verification was not bypassed.",
  "required_action": "Trust the generated laboratory CA explicitly, then execute the documented Playwright browser matrix.",
  "tokens_recorded": false
}
EOF
echo "${OUTPUT}"
exit 2
