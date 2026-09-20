#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTPUT="${ROOT}/artifacts/readiness/cross-tenant-results.json"
mkdir -p "$(dirname "${OUTPUT}")"
cd "${ROOT}"

tests=(
  apps/api/tests/test_policy.py::test_wrong_tenant_denied
  apps/api/tests/test_orchestrator.py::test_other_tenant_cannot_cancel_job
  apps/api/tests/test_asset_graph.py::test_graph_and_attack_paths_are_tenant_isolated
  apps/api/tests/test_domain_expansion_services.py::test_connector_inventory_is_tenant_isolated
  apps/api/tests/test_domain_expansion_services.py::test_worker_revalidation_rejects_cross_tenant_and_mutable_connector
  apps/api/tests/test_phase3_services.py::test_evidence_tenant_isolation
  apps/api/tests/test_production_readiness_closure.py::test_dead_letter_cross_tenant_and_unknown_queue_are_denied
  apps/api/tests/test_execution_api_contracts.py::test_scan_profile_and_adapter_api_contracts_are_tenant_scoped
)

.venv/bin/pytest -q --no-cov "${tests[@]}"
jq -n --arg executed_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --argjson count "${#tests[@]}" \
  '{status:"passed",executed_at:$executed_at,test_count:$count,
    layers:["policy","orchestrator","graph","connector","worker","evidence","dlq","execution_api"],
    synthetic_data_only:true}' > "${OUTPUT}"
echo "${OUTPUT}"
