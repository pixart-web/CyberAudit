#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTPUT="${ROOT}/artifacts/readiness/signing-results.json"
mkdir -p "$(dirname "${OUTPUT}")"
cat > "${OUTPUT}" <<EOF
{
  "status": "blocked",
  "signing_mode": "sigstore-keyless",
  "local_key_generated": false,
  "reason": "Keyless signing requires the GitHub Actions OIDC identity in the protected release workflow.",
  "required_action": "Satisfy readiness-gate, create the immutable tag through the controlled workflow, and review its Sigstore bundles."
}
EOF
echo "${OUTPUT}"
exit 2
