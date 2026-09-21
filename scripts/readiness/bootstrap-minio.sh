#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUNTIME="${ROOT}/infrastructure/readiness/runtime"
READINESS_DIR="${ROOT}/infrastructure/readiness"
COMPOSE=(docker-compose --env-file "${RUNTIME}/readiness.env" -f "${READINESS_DIR}/compose.production-like.yml")

set -a
# shellcheck disable=SC1090
source "${RUNTIME}/readiness.env"
set +a

${COMPOSE[@]} up -d minio-client
MC=(${COMPOSE[@]} exec -T minio-client mc)
${MC[@]} alias set readiness https://minio:9000 \
  "${MINIO_ROOT_USER}" "${MINIO_ROOT_PASSWORD}" --api S3v4 >/dev/null
${MC[@]} mb --ignore-existing --with-lock readiness/cyberaudit-readiness >/dev/null
${MC[@]} mb --ignore-existing readiness/cyberaudit-quarantine >/dev/null
${MC[@]} version enable readiness/cyberaudit-readiness >/dev/null
${MC[@]} anonymous set none readiness/cyberaudit-readiness >/dev/null
${MC[@]} anonymous set none readiness/cyberaudit-quarantine >/dev/null

echo "MinIO private versioned buckets are ready; anonymous access is disabled."
