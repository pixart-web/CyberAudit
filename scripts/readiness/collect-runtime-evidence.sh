#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
READINESS_DIR="${ROOT}/infrastructure/readiness"
RUNTIME="${READINESS_DIR}/runtime"
OUTPUT_DIR="${ROOT}/artifacts/readiness"
COMPOSE=(docker-compose --env-file "${RUNTIME}/readiness.env" -f "${READINESS_DIR}/compose.production-like.yml")

mkdir -p "${OUTPUT_DIR}"
"${COMPOSE[@]}" ps --format json \
  | jq -s 'map({name:.Name,service:.Service,image:.Image,state:.State,health:.Health,status:.Status,ports:.Ports})' \
  > "${OUTPUT_DIR}/production-like-services.json"

curl --fail --silent --show-error \
  --cacert "${RUNTIME}/tls/ca.crt" \
  --resolve cyberaudit.localhost:18443:127.0.0.1 \
  https://cyberaudit.localhost:18443/ready \
  | jq -e 'select(.status == "ready" and .dependencies.postgresql == "ok" and .dependencies.redis == "ok")' \
  > "${OUTPUT_DIR}/api-readiness.json"

curl --fail --silent --show-error \
  --cacert "${RUNTIME}/tls/ca.crt" \
  --resolve idp.localhost:18444:127.0.0.1 \
  https://idp.localhost:18444/realms/cyberaudit-readiness/.well-known/openid-configuration \
  | jq -e '{
      issuer,
      authorization_endpoint,
      token_endpoint,
      jwks_uri,
      code_challenge_methods_supported,
      supports_pkce_s256: (.code_challenge_methods_supported | index("S256") != null)
    } | select(.issuer == "https://idp.localhost:18444/realms/cyberaudit-readiness" and .supports_pkce_s256)' \
  > "${OUTPUT_DIR}/keycloak-discovery.json"

"${COMPOSE[@]}" exec -T vault sh -c \
  'VAULT_ADDR=https://127.0.0.1:8200 VAULT_CACERT=/run/tls/ca.crt vault status -format=json' \
  | jq -e '{initialized, sealed, version, storage_type, ha_enabled} | select(.initialized and (.sealed | not))' \
  > "${OUTPUT_DIR}/vault-status.json"

"${COMPOSE[@]}" exec -T postgres psql -X -A -t \
  -U cyberaudit_migration -d cyberaudit \
  -c "SELECT json_build_object('migration_head', version_num, 'database', current_database()) FROM alembic_version" \
  | jq -e 'select(.migration_head | length > 0)' \
  > "${OUTPUT_DIR}/migration-head.json"

echo "${OUTPUT_DIR}"
