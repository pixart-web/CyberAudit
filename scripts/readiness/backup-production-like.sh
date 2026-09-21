#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
READINESS_DIR="${ROOT}/infrastructure/readiness"
RUNTIME="${READINESS_DIR}/runtime"
OUTPUT_DIR="${ROOT}/artifacts/readiness/backups"
IDENTITY="${RUNTIME}/private/backup-age-identity.txt"
COMPOSE=(docker-compose --env-file "${RUNTIME}/readiness.env" -f "${READINESS_DIR}/compose.production-like.yml")
TEMPORARY="$(mktemp -d "${RUNTIME}/backup-work.XXXXXX")"
trap 'rm -rf "${TEMPORARY}"' EXIT
umask 077

mkdir -p "${OUTPUT_DIR}" "${RUNTIME}/private" "${TEMPORARY}/bundle/minio" "${TEMPORARY}/bundle/configuration"
if [[ ! -f "${IDENTITY}" ]]; then
  age-keygen -o "${IDENTITY}" >/dev/null
  chmod 600 "${IDENTITY}"
fi
recipient="$(age-keygen -y "${IDENTITY}")"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
backup_id="cyberaudit-readiness-${timestamp}"

"${COMPOSE[@]}" exec -T postgres pg_dump \
  --format=custom --no-owner --no-acl \
  -U cyberaudit_migration -d cyberaudit \
  > "${TEMPORARY}/bundle/postgres.dump"

"${COMPOSE[@]}" exec -T postgres psql -X -A -t \
  -U cyberaudit_migration -d cyberaudit -c "
    SELECT json_build_object(
      'organizations',(SELECT count(*) FROM organizations),
      'users',(SELECT count(*) FROM users),
      'roles',(SELECT count(*) FROM roles),
      'permissions',(SELECT count(*) FROM permissions),
      'clients',(SELECT count(*) FROM clients),
      'engagements',(SELECT count(*) FROM engagements),
      'assets',(SELECT count(*) FROM assets),
      'findings',(SELECT count(*) FROM findings),
      'audit_logs',(SELECT count(*) FROM audit_logs),
      'incidents',(SELECT count(*) FROM incidents),
      'knowledge_nodes',(SELECT count(*) FROM knowledge_nodes),
      'zero_trust_assessments',(SELECT count(*) FROM zero_trust_assessments)
    )" | jq -e '.' > "${TEMPORARY}/bundle/database-counts.json"

"${COMPOSE[@]}" run --rm --no-deps --entrypoint /bin/sh \
  -v "${TEMPORARY}/bundle/minio:/backup" minio-client -c '
    set -eu
    mc alias set readiness https://minio:9000 "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD" --api S3v4 >/dev/null
    printf "%s\n" "{\"synthetic\":true,\"purpose\":\"restore-validation\"}" | mc pipe readiness/cyberaudit-readiness/readiness/backup-marker.json >/dev/null
    mc mirror --overwrite readiness/cyberaudit-readiness /backup >/dev/null
  '

cp "${READINESS_DIR}/compose.production-like.yml" "${TEMPORARY}/bundle/configuration/"
cp "${ROOT}/docker-compose.yml" "${TEMPORARY}/bundle/configuration/"
cp "${ROOT}/infrastructure/helm/cyberaudit/Chart.yaml" "${TEMPORARY}/bundle/configuration/"
cp "${ROOT}/infrastructure/helm/cyberaudit/values.yaml" "${TEMPORARY}/bundle/configuration/"
git -C "${ROOT}" rev-parse HEAD > "${TEMPORARY}/bundle/commit.txt"
printf '%s\n' '0.2.0' > "${TEMPORARY}/bundle/application-version.txt"
printf '%s\n' '0015' > "${TEMPORARY}/bundle/schema-version.txt"

(cd "${TEMPORARY}/bundle" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 shasum -a 256) \
  > "${TEMPORARY}/bundle/SHA256SUMS"
tar -C "${TEMPORARY}" -czf "${TEMPORARY}/${backup_id}.tar.gz" bundle
encrypted="${OUTPUT_DIR}/${backup_id}.tar.gz.age"
age --recipient "${recipient}" --output "${encrypted}" "${TEMPORARY}/${backup_id}.tar.gz"

encrypted_checksum="$(shasum -a 256 "${encrypted}" | awk '{print $1}')"
encrypted_size="$(stat -f '%z' "${encrypted}")"
object_count="$(find "${TEMPORARY}/bundle/minio" -type f | wc -l | tr -d ' ')"
manifest="${OUTPUT_DIR}/${backup_id}.manifest.json"
jq -n \
  --arg backup_id "${backup_id}" \
  --arg created_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg archive "$(basename "${encrypted}")" \
  --arg checksum "${encrypted_checksum}" \
  --argjson size_bytes "${encrypted_size}" \
  --argjson object_count "${object_count}" \
  --slurpfile counts "${TEMPORARY}/bundle/database-counts.json" \
  '{schema_version:"1.0",application_version:"0.2.0",backup_id:$backup_id,created_at:$created_at,encrypted:true,archive:$archive,sha256:$checksum,size_bytes:$size_bytes,database_counts:$counts[0],minio_object_count:$object_count,synthetic_data_only:true}' \
  > "${manifest}"
cp "${manifest}" "${ROOT}/artifacts/readiness/backup-results.json"
printf '%s\n' "${manifest}" > "${OUTPUT_DIR}/latest-manifest.path"
echo "${manifest}"
