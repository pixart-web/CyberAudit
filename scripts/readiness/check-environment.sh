#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT="${1:-${SCRIPT_DIR}/../../artifacts/readiness/environment-check.json}"

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required to produce the readiness environment report" >&2
  exit 2
fi

exec python3 "${SCRIPT_DIR}/environment_check.py" "${OUTPUT}"
