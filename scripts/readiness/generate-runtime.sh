#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
READINESS_DIR="${ROOT}/infrastructure/readiness"
RUNTIME="${READINESS_DIR}/runtime"
TLS_DIR="${RUNTIME}/tls"
PRIVATE_DIR="${TLS_DIR}/private"
ENV_FILE="${RUNTIME}/readiness.env"

umask 077
mkdir -p "${PRIVATE_DIR}" "${RUNTIME}/keycloak" "${RUNTIME}/vault" \
  "${RUNTIME}/private" "${RUNTIME}/minio-certs/CAs"

random_hex() {
  openssl rand -hex "$1"
}

if [[ ! -f "${PRIVATE_DIR}/ca.key" ]]; then
  openssl genrsa -out "${PRIVATE_DIR}/ca.key" 3072 >/dev/null 2>&1
  openssl req -x509 -new -sha256 -days 30 \
    -key "${PRIVATE_DIR}/ca.key" \
    -subj "/CN=CyberAudit Readiness Laboratory CA/O=CyberAudit Synthetic Laboratory" \
    -out "${TLS_DIR}/ca.crt"
fi

if [[ ! -f "${PRIVATE_DIR}/service.key" ]]; then
  openssl genrsa -out "${PRIVATE_DIR}/service.key" 3072 >/dev/null 2>&1
  openssl req -new -sha256 \
    -key "${PRIVATE_DIR}/service.key" \
    -config "${READINESS_DIR}/tls/openssl.cnf" \
    -out "${RUNTIME}/private/service.csr"
  openssl x509 -req -sha256 -days 14 \
    -in "${RUNTIME}/private/service.csr" \
    -CA "${TLS_DIR}/ca.crt" \
    -CAkey "${PRIVATE_DIR}/ca.key" \
    -CAcreateserial \
    -extensions req_ext \
    -extfile "${READINESS_DIR}/tls/openssl.cnf" \
    -out "${TLS_DIR}/service.crt"
fi

chmod 600 "${PRIVATE_DIR}"/*.key
chmod 644 "${TLS_DIR}"/*.crt
cp "${TLS_DIR}/service.crt" "${RUNTIME}/minio-certs/public.crt"
cp "${PRIVATE_DIR}/service.key" "${RUNTIME}/minio-certs/private.key"
cp "${TLS_DIR}/ca.crt" "${RUNTIME}/minio-certs/CAs/readiness-ca.crt"

if [[ ! -f "${ENV_FILE}" ]]; then
  postgres_password="$(random_hex 24)"
  runtime_password="$(random_hex 24)"
  minio_user="readiness$(random_hex 6)"
  minio_password="$(random_hex 24)"
  keycloak_admin_password="$(random_hex 24)"
  viewer_password="$(random_hex 16)"
  analyst_password="$(random_hex 16)"
  admin_password="$(random_hex 16)"
  grafana_password="$(random_hex 20)"
  jwt_secret="$(random_hex 32)"
  encryption_key="$(random_hex 32)"
  minio_kms_key="$(openssl rand -base64 32 | tr -d '\n')"

  {
    printf 'POSTGRES_PASSWORD=%s\n' "${postgres_password}"
    printf 'CYBERAUDIT_RUNTIME_DB_PASSWORD=%s\n' "${runtime_password}"
    printf 'MINIO_ROOT_USER=%s\n' "${minio_user}"
    printf 'MINIO_ROOT_PASSWORD=%s\n' "${minio_password}"
    printf 'MINIO_KMS_SECRET_KEY=cyberaudit-readiness:%s\n' "${minio_kms_key}"
    printf 'AWS_ACCESS_KEY_ID=%s\n' "${minio_user}"
    printf 'AWS_SECRET_ACCESS_KEY=%s\n' "${minio_password}"
    printf 'KC_BOOTSTRAP_ADMIN_USERNAME=readiness-admin\n'
    printf 'KC_BOOTSTRAP_ADMIN_PASSWORD=%s\n' "${keycloak_admin_password}"
    printf 'KC_HEALTH_ENABLED=true\n'
    printf 'GF_SECURITY_ADMIN_USER=readiness-admin\n'
    printf 'GF_SECURITY_ADMIN_PASSWORD=%s\n' "${grafana_password}"
    printf 'ENVIRONMENT=staging\n'
    printf 'DATABASE_URL=postgresql+asyncpg://cyberaudit_runtime:%s@postgres:5432/cyberaudit\n' "${runtime_password}"
    printf 'DATABASE_RUNTIME_ROLE=cyberaudit_runtime\n'
    printf 'RLS_REQUIRED=true\n'
    printf 'REDIS_URL=rediss://redis:6379/0?ssl_ca_certs=/run/tls/ca.crt\n'
    printf 'JWT_SECRET=%s\n' "${jwt_secret}"
    printf 'ENCRYPTION_KEY=%s\n' "${encryption_key}"
    printf 'UPLOAD_DIR=/data/uploads\n'
    printf 'APP_ORIGIN=https://cyberaudit.localhost:18443\n'
    printf 'ALLOWED_HOSTS=["cyberaudit.localhost","api","localhost"]\n'
    printf 'REQUIRE_HTTPS=true\nSECURE_COOKIES=true\n'
    printf 'AUTHENTICATION_MODE=oidc\nLOCAL_AUTH_ENABLED=false\nOIDC_ENABLED=true\n'
    printf 'OIDC_ISSUER=https://idp.localhost:18444/realms/cyberaudit-readiness\n'
    printf 'OIDC_CLIENT_ID=cyberaudit-web\n'
    printf 'OIDC_CLIENT_SECRET_REFERENCE=\n'
    printf 'OIDC_REDIRECT_URI=https://cyberaudit.localhost:18443/auth/callback\n'
    printf 'OIDC_ALLOWED_DOMAINS=["example.test"]\nOIDC_REQUIRED_GROUP=\n'
    printf 'MFA_REQUIRED=true\nWEBAUTHN_ENABLED=true\nWEBAUTHN_RP_ID=cyberaudit.localhost\n'
    printf 'WEBAUTHN_ORIGINS=["https://cyberaudit.localhost:18443"]\n'
    printf 'SECRET_PROVIDER=vault\nVAULT_ADDRESS=https://vault:8200\nVAULT_TOKEN_FILE=/run/secrets/vault/token\n'
    printf 'OBJECT_STORAGE_PROVIDER=s3\nOBJECT_STORAGE_BUCKET=cyberaudit-readiness\n'
    printf 'OBJECT_STORAGE_ENDPOINT=https://minio:9000\nOBJECT_STORAGE_REGION=eu-west-1\n'
    printf 'CONNECTOR_MODE=import\nRUNNER_TYPE=docker_ephemeral\n'
    printf 'RUNNER_CONTROLLER_URL=https://runner-controller:9443\n'
    printf 'TELEMETRY_ENABLED=false\nSSL_CERT_FILE=/run/tls/ca.crt\nAWS_CA_BUNDLE=/run/tls/ca.crt\n'
    printf 'READINESS_EVIDENCE_MANIFEST=/app/artifacts/readiness/evidence-manifest.json\n'
    printf 'NEXT_PUBLIC_API_URL=https://cyberaudit.localhost:18443/api/v1\n'
    printf 'VIEWER_PASSWORD=%s\nANALYST_PASSWORD=%s\nADMIN_PASSWORD=%s\n' \
      "${viewer_password}" "${analyst_password}" "${admin_password}"
  } > "${ENV_FILE}"
  chmod 600 "${ENV_FILE}"
fi

# Preserve generated secrets while adding newly introduced, non-secret settings
# to runtime files created by an earlier revision of the readiness harness.
if ! grep -q '^READINESS_EVIDENCE_MANIFEST=' "${ENV_FILE}"; then
  printf 'READINESS_EVIDENCE_MANIFEST=/app/artifacts/readiness/evidence-manifest.json\n' >> "${ENV_FILE}"
fi
if ! grep -q '^AWS_CA_BUNDLE=' "${ENV_FILE}"; then
  printf 'AWS_CA_BUNDLE=/run/tls/ca.crt\n' >> "${ENV_FILE}"
fi
if ! grep -q '^MINIO_KMS_SECRET_KEY=' "${ENV_FILE}"; then
  printf 'MINIO_KMS_SECRET_KEY=cyberaudit-readiness:%s\n' \
    "$(openssl rand -base64 32 | tr -d '\n')" >> "${ENV_FILE}"
fi

replace_setting() {
  local key="$1" value="$2" temporary="${ENV_FILE}.tmp"
  awk -v key="${key}" -v value="${value}" '
    BEGIN { replaced = 0 }
    index($0, key "=") == 1 { print key "=" value; replaced = 1; next }
    { print }
    END { if (!replaced) print key "=" value }
  ' "${ENV_FILE}" > "${temporary}"
  mv "${temporary}" "${ENV_FILE}"
}
replace_setting OIDC_CLIENT_SECRET_REFERENCE ""
replace_setting OIDC_REQUIRED_GROUP ""
chmod 600 "${ENV_FILE}"

set -a
# shellcheck disable=SC1090
source "${ENV_FILE}"
set +a
sed \
  -e "s/__VIEWER_PASSWORD__/${VIEWER_PASSWORD}/g" \
  -e "s/__ANALYST_PASSWORD__/${ANALYST_PASSWORD}/g" \
  -e "s/__ADMIN_PASSWORD__/${ADMIN_PASSWORD}/g" \
  "${READINESS_DIR}/keycloak/realm.template.json" \
  > "${RUNTIME}/keycloak/cyberaudit-readiness-realm.json"
chmod 600 "${RUNTIME}/keycloak/cyberaudit-readiness-realm.json"

echo "Generated readiness runtime material under ${RUNTIME}"
