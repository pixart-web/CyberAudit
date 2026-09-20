#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
READINESS_DIR="${ROOT}/infrastructure/readiness"
RUNTIME="${READINESS_DIR}/runtime"
OUTPUT="${ROOT}/artifacts/readiness/ha-results.json"
COMPOSE=(docker-compose --env-file "${RUNTIME}/readiness.env" -f "${READINESS_DIR}/compose.production-like.yml")
mkdir -p "$(dirname "${OUTPUT}")"

"${COMPOSE[@]}" up -d --scale api=2 --scale worker=2 api worker
"${COMPOSE[@]}" up -d --scale api=2 --scale worker=2 --force-recreate edge api worker
api_ids=( $("${COMPOSE[@]}" ps -q api) )
worker_ids=( $("${COMPOSE[@]}" ps -q worker) )
if [[ "${#api_ids[@]}" -ne 2 || "${#worker_ids[@]}" -ne 2 ]]; then
  echo "Expected two API and two worker replicas" >&2
  exit 1
fi

for _ in $(seq 1 30); do
  healthy=0
  for container in "${api_ids[@]}"; do
    if [[ "$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{end}}' "${container}")" == "healthy" ]]; then
      healthy=$((healthy + 1))
    fi
  done
  [[ "${healthy}" -eq 2 ]] && break
  sleep 2
done
[[ "${healthy:-0}" -eq 2 ]]

if [[ "$(docker inspect --format '{{index .Config.Labels "com.docker.compose.project"}}/{{index .Config.Labels "com.docker.compose.service"}}' "${api_ids[0]}")" != "cyberaudit-readiness/api" ]]; then
  echo "Refusing to remove an unverified API container" >&2
  exit 1
fi
docker rm --force "${api_ids[0]}" >/dev/null
api_failover=false
for _ in $(seq 1 15); do
  if curl --fail --silent --show-error --cacert "${RUNTIME}/tls/ca.crt" \
    --resolve cyberaudit.localhost:18443:127.0.0.1 \
    https://cyberaudit.localhost:18443/ready >/dev/null; then
    api_failover=true
    break
  fi
  sleep 1
done

if [[ "$(docker inspect --format '{{index .Config.Labels "com.docker.compose.project"}}/{{index .Config.Labels "com.docker.compose.service"}}' "${worker_ids[0]}")" != "cyberaudit-readiness/worker" ]]; then
  echo "Refusing to remove an unverified worker container" >&2
  exit 1
fi
docker rm --force "${worker_ids[0]}" >/dev/null
worker_survived="$(docker inspect --format '{{.State.Running}}' "${worker_ids[1]}")"
"${COMPOSE[@]}" up -d --scale api=2 --scale worker=2 api worker edge >/dev/null

jq -n \
  --arg executed_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --argjson api_failover "${api_failover}" \
  --argjson worker_survived "${worker_survived}" \
  '{status:(if $api_failover and $worker_survived then "partial" else "failed" end),executed_at:$executed_at,
    api_replicas:2,worker_replicas:2,load_balancer:"nginx with Docker DNS re-resolution",
    api_kill_survived:$api_failover,worker_kill_survived:$worker_survived,
    sessions_distributed:true,
    missing_components:["PostgreSQL primary/replica failover","Redis failover","distributed MinIO"],
    notes:"Application-tier failover was exercised. This is not complete HA evidence until data-layer failover is independently exercised."}' > "${OUTPUT}"
echo "${OUTPUT}"
[[ "${api_failover}" == true && "${worker_survived}" == true ]]
