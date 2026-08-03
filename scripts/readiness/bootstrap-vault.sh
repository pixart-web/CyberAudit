#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
READINESS_DIR="${ROOT}/infrastructure/readiness"
RUNTIME="${READINESS_DIR}/runtime"
COMPOSE=(docker-compose --env-file "${RUNTIME}/readiness.env" -f "${READINESS_DIR}/compose.production-like.yml")
INIT_FILE="${RUNTIME}/private/vault-init.json"
TOKEN_FILE="${RUNTIME}/vault/token"

umask 077
vault_exec() {
  local environment=(-e VAULT_ADDR=https://127.0.0.1:8200 -e VAULT_CACERT=/run/tls/ca.crt)
  if [[ -n "${VAULT_TOKEN:-}" ]]; then
    environment+=(-e "VAULT_TOKEN=${VAULT_TOKEN}")
  fi
  "${COMPOSE[@]}" exec -T "${environment[@]}" vault vault "$@"
}

health=""
for _ in $(seq 1 60); do
  health="$(vault_exec status -format=json 2>/dev/null || true)"
  if [[ -n "${health}" ]]; then
    break
  fi
  sleep 2
done
if [[ -z "${health}" ]]; then
  echo "Vault did not become reachable" >&2
  exit 1
fi
if [[ "$(jq -r '.initialized' <<<"${health}")" == "false" ]]; then
  vault_exec operator init -key-shares=1 -key-threshold=1 -format=json > "${INIT_FILE}"
  chmod 600 "${INIT_FILE}"
fi

unseal_key="$(jq -r '.unseal_keys_b64[0]' "${INIT_FILE}")"
root_token="$(jq -r '.root_token' "${INIT_FILE}")"
vault_exec operator unseal "${unseal_key}" >/dev/null

export VAULT_TOKEN="${root_token}"
if ! vault_exec secrets list -format=json | jq -e 'has("cyberaudit/")' >/dev/null; then
  vault_exec secrets enable -path=cyberaudit kv-v2 >/dev/null
fi
vault_exec policy write cyberaudit-readonly /vault/config/cyberaudit-readonly.hcl >/dev/null
if ! vault_exec audit list -format=json | jq -e 'has("file/")' >/dev/null; then
  vault_exec audit enable file file_path=/vault/data/audit.log >/dev/null
fi

set -a
# shellcheck disable=SC1090
source "${RUNTIME}/readiness.env"
set +a
vault_exec kv put cyberaudit/organizations/platform/storage \
  access_key="${MINIO_ROOT_USER}" secret_key="${MINIO_ROOT_PASSWORD}" >/dev/null
api_token="$(vault_exec token create -policy=cyberaudit-readonly -period=1h -renewable=true -field=token)"
printf '%s\n' "${api_token}" > "${TOKEN_FILE}"
chmod 600 "${TOKEN_FILE}"

echo "Vault initialized/unsealed and a renewable read-only workload token was issued."
