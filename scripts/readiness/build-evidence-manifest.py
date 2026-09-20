#!/usr/bin/env python3
"""Build a fail-closed manifest from locally collected, sanitized artifacts."""

from __future__ import annotations

import hashlib
import json
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUTPUT_DIR = ROOT / "artifacts" / "readiness"
OUTPUT = OUTPUT_DIR / "evidence-manifest.json"
VERSION = "0.2.0"
ENVIRONMENT = "staging"
HUMAN_REVIEW_REQUIRED = frozenset(
    {
        "oidc_second_provider",
        "webauthn",
        "backup",
        "restore",
        "ha",
        "dr",
        "signing",
        "provenance",
        "vulnerabilities",
        "release_validation",
        "upgrade",
        "rollback",
        "external_assessment",
    }
)

CHECKS: tuple[tuple[str, str, str | None], ...] = (
    (
        "configuration",
        "Production-like services and API dependencies",
        "api-readiness.json",
    ),
    (
        "oidc_keycloak",
        "Keycloak discovery and PKCE configuration",
        "keycloak-discovery.json",
    ),
    ("oidc_second_provider", "Second independent OIDC provider", None),
    ("webauthn", "WebAuthn ceremony", "webauthn-browser-results.json"),
    ("rls", "PostgreSQL tenant RLS", "rls-results.json"),
    (
        "cross_tenant_tests",
        "Cross-tenant application tests",
        "cross-tenant-results.json",
    ),
    ("dlq", "Dead-letter queue recovery", "dlq-results.json"),
    ("secret_provider", "Vault workload provider", "provider-results.json"),
    ("object_storage", "Private tenant-scoped object storage", "provider-results.json"),
    (
        "docker_runner",
        "Restricted Docker runner primitive",
        "docker-runner-results.json",
    ),
    (
        "kubernetes_runner",
        "Restricted Kubernetes runner primitive",
        "kubernetes-runner-results.json",
    ),
    ("backup", "Encrypted backup", "backup-results.json"),
    ("restore", "Isolated restore drill", "restore-results.json"),
    ("ha", "High-availability behavior", "ha-results.json"),
    ("dr", "Disaster-recovery drill", "dr-results.json"),
    ("sbom", "CycloneDX and SPDX SBOM", "sbom-results.json"),
    ("signing", "Keyless release signature", "signing-results.json"),
    ("provenance", "Build provenance", "provenance-results.json"),
    (
        "vulnerabilities",
        "Repository and image vulnerability scan",
        "vulnerability-results.json",
    ),
    ("coverage", "Backend and frontend coverage", "coverage-results.json"),
    ("migrations", "Migration head on PostgreSQL", "migration-head.json"),
    ("release_validation", "Release validation", None),
    ("upgrade", "Upgrade rehearsal", None),
    ("rollback", "Rollback rehearsal", None),
    ("external_assessment", "Independent external security assessment", None),
)


def checksum(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git_commit() -> str:
    value = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if len(value) != 40:
        raise RuntimeError("A full Git commit is required")
    return value


def main() -> None:
    now = datetime.now(timezone.utc)
    evidence: list[dict[str, object]] = []
    for check_id, title, filename in CHECKS:
        artifact = OUTPUT_DIR / filename if filename else None
        artifact_available = bool(
            artifact and artifact.is_file() and artifact.stat().st_size > 0
        )
        reviewer = "automation:local-readiness-harness"
        human_approved = check_id not in HUMAN_REVIEW_REQUIRED
        review_path = OUTPUT_DIR / "reviews" / f"{check_id}.json"
        if (
            check_id in HUMAN_REVIEW_REQUIRED
            and artifact_available
            and review_path.is_file()
        ):
            review = json.loads(review_path.read_text(encoding="utf-8"))
            candidate_reviewer = str(review.get("reviewer", ""))
            human_approved = bool(
                review.get("approved") is True
                and candidate_reviewer
                and not candidate_reviewer.startswith("automation:")
                and review.get("artifact_checksum") == checksum(artifact)
            )
            if human_approved:
                reviewer = candidate_reviewer
        declared_status: str | None = None
        if artifact_available and artifact:
            try:
                payload = json.loads(artifact.read_text(encoding="utf-8"))
                if isinstance(payload, dict) and isinstance(payload.get("status"), str):
                    declared_status = payload["status"]
            except (UnicodeDecodeError, json.JSONDecodeError):
                declared_status = None
        artifact_passed = declared_status in {None, "passed", "generated", "ready"}
        passed = artifact_available and artifact_passed and human_approved
        status = (
            "passed"
            if passed
            else "failed" if declared_status == "failed" else "blocked"
        )
        evidence.append(
            {
                "check_id": check_id,
                "title": title,
                "status": status,
                "executed_at": now.isoformat(),
                "expires_at": (now + timedelta(hours=24)).isoformat(),
                "environment": ENVIRONMENT,
                "application_version": VERSION,
                "tool": "CyberAudit readiness harness",
                "tool_version": "1.0",
                "command_reference": f"make readiness-{check_id.replace('_', '-')}",
                "artifact_path": (
                    artifact.name if artifact_available and artifact else None
                ),
                "checksum": (
                    checksum(artifact) if artifact_available and artifact else None
                ),
                "reviewer": reviewer,
                "notes": (
                    "Sanitized synthetic validation artifact."
                    if passed
                    else (
                        "Evidence collected; independent human review is still required."
                        if artifact_available
                        and artifact_passed
                        and check_id in HUMAN_REVIEW_REQUIRED
                        else (
                            f"Artifact reports status '{declared_status}'; release gate remains closed."
                            if artifact_available and not artifact_passed
                            else "No valid evidence collected; release gate remains closed."
                        )
                    )
                ),
            }
        )
    document = {
        "schema_version": "1.0",
        "generated_at": now.isoformat(),
        "environment": ENVIRONMENT,
        "application_version": VERSION,
        "commit": git_commit(),
        "evidence": evidence,
    }
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(OUTPUT)


if __name__ == "__main__":
    main()
