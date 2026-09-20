#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTPUT="${ROOT}/artifacts/readiness/docker-runner-results.json"
IMAGE_TAG=python:3.12.13-alpine3.22

mkdir -p "$(dirname "${OUTPUT}")"
docker pull "${IMAGE_TAG}" >/dev/null
image="$(docker image inspect "${IMAGE_TAG}" --format '{{index .RepoDigests 0}}')"
if [[ "${image}" != *@sha256:* ]]; then
  echo "Runner image did not resolve to an immutable digest" >&2
  exit 1
fi

result="$(docker run --rm \
  --name cyberaudit-readiness-fixed-runner \
  --user 65532:65532 \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --memory 64m \
  --cpus 0.25 \
  --pids-limit 16 \
  --network none \
  --entrypoint python \
  "${image}" \
  -c "import hashlib,json; print(json.dumps({'status':'passed','sha256':hashlib.sha256(b'cyberaudit-readiness').hexdigest()}))")"

jq -n \
  --arg image "${image}" \
  --argjson execution "${result}" \
  '{status:"passed", simulated:false, image:$image, isolation:{new_container:true,run_as_non_root:true,read_only:true,tmpfs:true,capabilities:"drop_all",no_new_privileges:true,memory_mb:64,cpu:0.25,pids:16,network:"none",docker_socket:false}, execution:$execution}' \
  > "${OUTPUT}"
echo "${OUTPUT}"
