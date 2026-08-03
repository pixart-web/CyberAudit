#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
READINESS_DIR="${ROOT}/infrastructure/readiness"
RUNTIME="${READINESS_DIR}/runtime"
OUTPUT_DIR="${ROOT}/artifacts/readiness/backups"
IDENTITY="${RUNTIME}/private/backup-age-identity.txt"
RESULT="${ROOT}/artifacts/readiness/restore-results.json"
COMPOSE=(docker-compose --env-file "${RUNTIME}/readiness.env" -f "${READINESS_DIR}/compose.production-like.yml")
TEMPORARY="$(mktemp -d "${RUNTIME}/restore-work.XXXXXX")"
trap 'rm -rf "${TEMPORARY}"' EXIT
started_epoch="$(date +%s)"

manifest="${BACKUP_MANIFEST:-$(cat "${OUTPUT_DIR}/latest-manifest.path")}"
case "${manifest}" in
  "${OUTPUT_DIR}"/*.manifest.json) ;;
  *) echo "Backup manifest is outside the controlled directory" >&2; exit 2 ;;
esac
archive="${OUTPUT_DIR}/$(jq -r '.archive' "${manifest}")"
expected_checksum="$(jq -r '.sha256' "${manifest}")"
actual_checksum="$(shasum -a 256 "${archive}" | awk '{print $1}')"
[[ "${actual_checksum}" == "${expected_checksum}" ]]

age --decrypt --identity "${IDENTITY}" --output "${TEMPORARY}/backup.tar.gz" "${archive}"
tar -C "${TEMPORARY}" -xzf "${TEMPORARY}/backup.tar.gz"
(cd "${TEMPORARY}/bundle" && shasum -a 256 -c SHA256SUMS >/dev/null)

"${COMPOSE[@]}" exec -T postgres dropdb --if-exists -U cyberaudit_migration cyberaudit_restore_drill
"${COMPOSE[@]}" exec -T postgres createdb -U cyberaudit_migration cyberaudit_restore_drill
"${COMPOSE[@]}" exec -T postgres pg_restore --exit-on-error --no-owner --no-acl \
  -U cyberaudit_migration -d cyberaudit_restore_drill < "${TEMPORARY}/bundle/postgres.dump"

"${COMPOSE[@]}" exec -T postgres psql -X -A -t \
  -U cyberaudit_migration -d cyberaudit_restore_drill -c "
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
    )" | jq -e '.' > "${TEMPORARY}/restored-counts.json"
jq -e --argjson restored "$(cat "${TEMPORARY}/restored-counts.json")" '.database_counts == $restored' "${manifest}" >/dev/null

mkdir -p "${TEMPORARY}/restored-minio"
"${COMPOSE[@]}" run --rm --no-deps --entrypoint /bin/sh \
  -v "${TEMPORARY}/bundle/minio:/backup:ro" \
  -v "${TEMPORARY}/restored-minio:/restored" minio-client -c '
    set -eu
    mc alias set readiness https://minio:9000 "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD" --api S3v4 >/dev/null
    mc rb --force readiness/cyberaudit-readiness-restore >/dev/null 2>&1 || true
    mc mb readiness/cyberaudit-readiness-restore >/dev/null
    mc anonymous set none readiness/cyberaudit-readiness-restore >/dev/null
    mc mirror --overwrite /backup readiness/cyberaudit-readiness-restore >/dev/null
    mc mirror --overwrite readiness/cyberaudit-readiness-restore /restored >/dev/null
  '
(cd "${TEMPORARY}/bundle/minio" && find . -type f -print0 | sort -z | xargs -0 shasum -a 256) > "${TEMPORARY}/expected-minio.sha256"
(cd "${TEMPORARY}/restored-minio" && find . -type f -print0 | sort -z | xargs -0 shasum -a 256) > "${TEMPORARY}/restored-minio.sha256"
cmp "${TEMPORARY}/expected-minio.sha256" "${TEMPORARY}/restored-minio.sha256"

completed_epoch="$(date +%s)"
backup_epoch="$(date -j -u -f '%Y-%m-%dT%H:%M:%SZ' "$(jq -r '.created_at' "${manifest}")" '+%s')"
jq -n \
  --arg executed_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg database cyberaudit_restore_drill \
  --argjson rto_seconds "$((completed_epoch - started_epoch))" \
  --argjson observed_rpo_seconds "$((started_epoch - backup_epoch))" \
  --slurpfile counts "${TEMPORARY}/restored-counts.json" \
  '{status:"passed",executed_at:$executed_at,isolated_database:$database,destructive_scope:"isolated_restore_database_and_restore_bucket_only",database_counts:$counts[0],database_counts_match:true,minio_checksums_match:true,encrypted_backup_verified:true,rto_seconds:$rto_seconds,observed_rpo_seconds:$observed_rpo_seconds,synthetic_data_only:true}' \
  > "${RESULT}"
echo "${RESULT}"
