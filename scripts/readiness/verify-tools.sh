#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPORT="${1:-${SCRIPT_DIR}/../../artifacts/readiness/environment-check.json}"

set +e
"${SCRIPT_DIR}/check-environment.sh" "${REPORT}"
check_status=$?
set -e

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required to display the readiness summary; inspect ${REPORT}" >&2
  exit 2
fi

jq '{summary, blocking: [.tools[] | select(.status == "blocking") | .tool]}' "${REPORT}"
exit "${check_status}"
