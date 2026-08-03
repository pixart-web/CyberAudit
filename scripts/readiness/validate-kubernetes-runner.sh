#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUNTIME="${ROOT}/infrastructure/readiness/runtime/kind"
OUTPUT="${ROOT}/artifacts/readiness/kubernetes-runner-results.json"
TEMPLATE="${ROOT}/infrastructure/readiness/kind/runner-job.template.yml"
CONTEXT=kind-cyberaudit-readiness
IMAGE_TAG=python:3.12.13-alpine3.22

mkdir -p "${RUNTIME}" "$(dirname "${OUTPUT}")"
image="$(docker image inspect "${IMAGE_TAG}" --format '{{index .RepoDigests 0}}')"
if [[ "${image}" != *@sha256:* ]]; then
  echo "Runner image did not resolve to an immutable digest" >&2
  exit 1
fi
sed "s|__RUNNER_IMAGE__|${image}|g" "${TEMPLATE}" > "${RUNTIME}/runner-job.yml"

kubectl --context "${CONTEXT}" delete job readiness-fixed-runner -n cyberaudit-runners --ignore-not-found >/dev/null
kubectl --context "${CONTEXT}" apply -f "${RUNTIME}/runner-job.yml" >/dev/null
kubectl --context "${CONTEXT}" wait --for=condition=complete job/readiness-fixed-runner -n cyberaudit-runners --timeout=90s >/dev/null
execution="$(kubectl --context "${CONTEXT}" logs job/readiness-fixed-runner -n cyberaudit-runners)"
pod_spec="$(kubectl --context "${CONTEXT}" get pod -n cyberaudit-runners -l app=readiness-fixed-runner -o json)"
job_spec="$(kubectl --context "${CONTEXT}" get job readiness-fixed-runner -n cyberaudit-runners -o json)"
namespace="$(kubectl --context "${CONTEXT}" get namespace cyberaudit-runners -o json)"
network_policy="$(kubectl --context "${CONTEXT}" get networkpolicy default-deny -n cyberaudit-runners -o json)"
temporary_output="$(mktemp "${OUTPUT}.XXXXXX")"
trap 'rm -f "${temporary_output}"' EXIT

jq -n \
  --arg image "${image}" \
  --argjson execution "${execution}" \
  --argjson pods "${pod_spec}" \
  --argjson job "${job_spec}" \
  --argjson namespace "${namespace}" \
  --argjson network_policy "${network_policy}" \
  '{
    status:"passed",
    simulated:false,
    image:$image,
    execution:$execution,
    validation:{
      pods:($pods.items|length),
      host_network:($pods.items[0].spec.hostNetwork // false),
      host_pid:($pods.items[0].spec.hostPID // false),
      service_account_token:$pods.items[0].spec.automountServiceAccountToken,
      run_as_non_root:$pods.items[0].spec.securityContext.runAsNonRoot,
      seccomp:$pods.items[0].spec.securityContext.seccompProfile.type,
      read_only:$pods.items[0].spec.containers[0].securityContext.readOnlyRootFilesystem,
      privilege_escalation:$pods.items[0].spec.containers[0].securityContext.allowPrivilegeEscalation,
      capabilities_dropped:$pods.items[0].spec.containers[0].securityContext.capabilities.drop,
      network_policy:$network_policy.metadata.name,
      pod_security:$namespace.metadata.labels["pod-security.kubernetes.io/enforce"],
      active_deadline_seconds:$job.spec.activeDeadlineSeconds,
      ttl_cleanup_seconds:$job.spec.ttlSecondsAfterFinished
    }
  }
  | select(
      .validation.pods == 1
      and .validation.host_network == false
      and .validation.host_pid == false
      and .validation.service_account_token == false
      and .validation.run_as_non_root == true
      and .validation.seccomp == "RuntimeDefault"
      and .validation.read_only == true
      and .validation.privilege_escalation == false
      and (.validation.capabilities_dropped | index("ALL") != null)
      and .validation.network_policy == "default-deny"
      and .validation.pod_security == "restricted"
      and .validation.active_deadline_seconds == 60
    )' \
  > "${temporary_output}"
test -s "${temporary_output}"
mv "${temporary_output}" "${OUTPUT}"
trap - EXIT
echo "${OUTPUT}"
