#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTPUT="${ROOT}/artifacts/readiness/webauthn-browser-results.json"
mkdir -p "$(dirname "${OUTPUT}")"
cat > "${OUTPUT}" <<EOF
{
  "status": "blocked",
  "virtual_authenticator_executed": false,
  "physical_authenticator_executed": false,
  "reason": "A trusted browser origin and an operator-controlled authenticator are required.",
  "required_action": "Complete the ceremony matrix in docs/testing/webauthn-browser-validation.md.",
  "private_keys_recorded": false
}
EOF
echo "${OUTPUT}"
exit 2
