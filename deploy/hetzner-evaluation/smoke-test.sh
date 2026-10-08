#!/usr/bin/env bash
# Black-box checks against a deployed instance. Read-only: no login, no writes.
set -uo pipefail
BASE="${1:?usage: smoke-test.sh https://host}"
fail=0
check() { # name, expected, actual
  if [[ "$3" == *"$2"* ]]; then echo "PASS  $1"; else echo "FAIL  $1 (expected '$2', got '$3')"; fail=1; fi
}
code() { curl -s -o /dev/null -m 15 -w '%{http_code}' "$@"; }

check "web serves login"            "200" "$(code -L "$BASE/login")"
check "api readiness (db+redis)"    "200" "$(code "$BASE/ready")"
check "api health"                  "200" "$(code "$BASE/health")"
check "setup status endpoint"       "200" "$(code "$BASE/api/v1/setup/status")"
check "auth required for data"      "401" "$(code "$BASE/api/v1/users")"
check "unauthenticated admin 401"   "401" "$(code -X POST -H 'Content-Type: application/json' -d '{}' "$BASE/api/v1/platform/organizations")"
HDRS=$(curl -sI -m 15 "$BASE/api/v1/setup/status")
check "nosniff header"              "nosniff" "$(echo "$HDRS" | tr 'A-Z' 'a-z')"
check "http redirects to https"     "30" "$(code "http://${BASE#https://}/login")"
if curl -s -m 15 "$BASE/openapi.json" | grep -q '"paths"'; then echo "FAIL  OpenAPI schema is publicly exposed"; fail=1; else echo "PASS  OpenAPI schema not publicly exposed"; fi
if curl -s -m 15 "$BASE/docs" | grep -qi swagger; then echo "FAIL  Swagger UI is publicly exposed"; fail=1; else echo "PASS  Swagger UI not publicly exposed"; fi
exit $fail
