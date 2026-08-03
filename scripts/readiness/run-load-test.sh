#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUNTIME="${ROOT}/infrastructure/readiness/runtime"
READINESS_DIR="${ROOT}/infrastructure/readiness"
OUTPUT_DIR="${ROOT}/artifacts/readiness/load-tests"
RAW="${OUTPUT_DIR}/k6-summary.json"
SUMMARY="${ROOT}/artifacts/readiness/load-results.json"
mkdir -p "${OUTPUT_DIR}"
COMPOSE=(docker-compose --env-file "${RUNTIME}/readiness.env" -f "${READINESS_DIR}/compose.production-like.yml")

"${COMPOSE[@]}" run --rm --no-deps \
  --user "$(id -u):$(id -g)" \
  -v "${ROOT}/scripts/readiness/load-test.js:/scripts/load-test.js:ro" \
  -v "${OUTPUT_DIR}:/output" \
  k6 run --quiet \
    --summary-export /output/k6-summary.json \
    --summary-trend-stats 'avg,min,med,max,p(90),p(95),p(99)' \
    /scripts/load-test.js

jq -n \
  --arg executed_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg operating_system "$(uname -s)" \
  --arg architecture "$(uname -m)" \
  --argjson cpu_count "$(sysctl -n hw.logicalcpu)" \
  --argjson memory_bytes "$(sysctl -n hw.memsize)" \
  --slurpfile report "${RAW}" \
  '{
    status:"partial",
    executed_at:$executed_at,
    synthetic_data_only:true,
    scope:["health","readiness","login_page"],
    pending_authenticated_scenarios:["login ceremony","dashboard","assets","identities","events","graph","reports","connector jobs"],
    hardware:{operating_system:$operating_system,architecture:$architecture,cpu_count:$cpu_count,memory_bytes:$memory_bytes},
    metrics:{
      requests:($report[0].metrics.http_reqs.values.count // $report[0].metrics.http_reqs.count),
      throughput_per_second:($report[0].metrics.http_reqs.values.rate // $report[0].metrics.http_reqs.rate),
      error_rate:($report[0].metrics.http_req_failed.values.rate // $report[0].metrics.http_req_failed.value),
      check_rate:($report[0].metrics.checks.values.rate // $report[0].metrics.checks.value),
      duration_ms:{
        p50:($report[0].metrics.http_req_duration.values.med // $report[0].metrics.http_req_duration.med),
        p95:($report[0].metrics.http_req_duration.values["p(95)"] // $report[0].metrics.http_req_duration["p(95)"]),
        p99:($report[0].metrics.http_req_duration.values["p(99)"] // $report[0].metrics.http_req_duration["p(99)"])
      }
    }
  }' > "${SUMMARY}"
echo "${SUMMARY}"
