#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
READINESS_DIR="${ROOT}/infrastructure/readiness"
ENV_FILE="${READINESS_DIR}/runtime/readiness.env"

if [[ ! -f "${ENV_FILE}" ]]; then
  echo "Readiness environment has not been generated."
  exit 0
fi
docker-compose --env-file "${ENV_FILE}" -f "${READINESS_DIR}/compose.production-like.yml" down
