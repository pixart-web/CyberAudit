#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT}"

scripts/readiness/build-evidence-manifest.py
PYTHONPATH=apps/api .venv/bin/python scripts/readiness/evaluate-gate.py

echo "The evidence gate is candidate. Publication must occur through the protected GitHub release workflow."
echo "This local command intentionally does not create or push a tag."
