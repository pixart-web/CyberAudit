#!/usr/bin/env python3
"""Evaluate the external evidence manifest without mutating readiness state."""

from __future__ import annotations

import json
from pathlib import Path

from cyberaudit.readiness import MANDATORY_CHECKS
from cyberaudit.readiness_evidence import validate_evidence_manifest

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "artifacts" / "readiness" / "evidence-manifest.json"
OUTPUT = ROOT / "artifacts" / "readiness" / "gate-results.json"


def main() -> None:
    validation = validate_evidence_manifest(
        MANIFEST, environment="staging", application_version="0.2.0"
    )
    statuses = {
        code: (
            validation.valid_checks[code].status
            if code in validation.valid_checks
            else "missing"
        )
        for code in MANDATORY_CHECKS
    }
    blockers = [code for code, status in statuses.items() if status != "passed"]
    state = "candidate" if not blockers and not validation.errors else "blocked"
    result = {
        "state": state,
        "environment": "staging",
        "application_version": "0.2.0",
        "manifest_checksum": validation.manifest_checksum,
        "manifest_errors": validation.errors,
        "checks": statuses,
        "blockers": blockers,
        "database_evidence_required_for_api_gate": True,
    }
    OUTPUT.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(OUTPUT)
    if state != "candidate":
        raise SystemExit(2)


if __name__ == "__main__":
    main()
