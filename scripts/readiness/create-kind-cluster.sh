#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CONFIG="${ROOT}/infrastructure/readiness/kind/cluster.yml"
CLUSTER=cyberaudit-readiness

if ! docker info >/dev/null 2>&1; then
  echo "Docker must be functional before Kind is started." >&2
  exit 1
fi
if kind get clusters | grep -Fxq "${CLUSTER}"; then
  echo "Kind cluster ${CLUSTER} already exists."
else
  kind create cluster --name "${CLUSTER}" --image kindest/node:v1.33.1 --config "${CONFIG}" --wait 180s
fi
kubectl --context "kind-${CLUSTER}" apply -f "${ROOT}/infrastructure/readiness/kind/namespace.yml"
kubectl --context "kind-${CLUSTER}" wait --for=condition=Ready nodes --all --timeout=120s
