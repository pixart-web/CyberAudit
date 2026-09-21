from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone

from cyberaudit.readiness_evidence import validate_evidence_manifest


def test_manifest_requires_matching_checksum_and_rejects_traversal(tmp_path) -> None:
    artifact = tmp_path / "result.json"
    artifact.write_text('{"status":"passed"}\n', encoding="utf-8")
    now = datetime.now(timezone.utc)
    base = {
        "schema_version": "1.0",
        "generated_at": now.isoformat(),
        "environment": "production-like",
        "application_version": "0.1.0-rc.1",
        "commit": "a" * 40,
        "evidence": [
            {
                "check_id": "configuration",
                "title": "Configuration validation",
                "status": "passed",
                "executed_at": now.isoformat(),
                "expires_at": (now + timedelta(hours=1)).isoformat(),
                "environment": "production-like",
                "application_version": "0.1.0-rc.1",
                "tool": "pytest",
                "tool_version": "1",
                "command_reference": "make readiness-evidence",
                "artifact_path": "result.json",
                "checksum": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                "reviewer": "automation:local",
                "notes": "Synthetic test artifact",
            }
        ],
    }
    manifest = tmp_path / "evidence-manifest.json"
    manifest.write_text(json.dumps(base), encoding="utf-8")
    result = validate_evidence_manifest(
        manifest,
        environment="production-like",
        application_version="0.1.0-rc.1",
        now=now,
    )
    assert set(result.valid_checks) == {"configuration"}
    assert result.errors == []

    base["evidence"][0]["artifact_path"] = "../result.json"
    manifest.write_text(json.dumps(base), encoding="utf-8")
    rejected = validate_evidence_manifest(
        manifest,
        environment="production-like",
        application_version="0.1.0-rc.1",
        now=now,
    )
    assert rejected.errors == ["unsafe_artifact_path:configuration"]


def test_manifest_rejects_empty_artifact(tmp_path) -> None:
    artifact = tmp_path / "empty.json"
    artifact.write_bytes(b"")
    now = datetime.now(timezone.utc)
    manifest = tmp_path / "evidence-manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "generated_at": now.isoformat(),
                "environment": "staging",
                "application_version": "0.2.0",
                "commit": "a" * 40,
                "evidence": [
                    {
                        "check_id": "configuration",
                        "title": "Configuration validation",
                        "status": "passed",
                        "executed_at": now.isoformat(),
                        "environment": "staging",
                        "application_version": "0.2.0",
                        "tool": "pytest",
                        "tool_version": "1",
                        "command_reference": "make readiness-evidence",
                        "artifact_path": artifact.name,
                        "checksum": hashlib.sha256(b"").hexdigest(),
                        "reviewer": "automation:local",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    result = validate_evidence_manifest(
        manifest,
        environment="staging",
        application_version="0.2.0",
        now=now,
    )

    assert result.errors == ["artifact_empty:configuration"]


def test_manifest_requires_human_reviewer_for_external_controls(tmp_path) -> None:
    artifact = tmp_path / "assessment.json"
    artifact.write_text('{"status":"passed"}\n', encoding="utf-8")
    now = datetime.now(timezone.utc)
    manifest = tmp_path / "evidence-manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "generated_at": now.isoformat(),
                "environment": "staging",
                "application_version": "0.2.0",
                "commit": "b" * 40,
                "evidence": [
                    {
                        "check_id": "external_assessment",
                        "title": "Independent security assessment",
                        "status": "passed",
                        "executed_at": now.isoformat(),
                        "environment": "staging",
                        "application_version": "0.2.0",
                        "tool": "external assessor",
                        "tool_version": "report-v1",
                        "command_reference": "review external report",
                        "artifact_path": artifact.name,
                        "checksum": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                        "reviewer": "automation:local",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    result = validate_evidence_manifest(
        manifest, environment="staging", application_version="0.2.0", now=now
    )

    assert result.errors == ["human_review_required:external_assessment"]
    assert "external_assessment" not in result.valid_checks


def test_manifest_rejects_expired_and_wrong_environment_evidence(tmp_path) -> None:
    now = datetime.now(timezone.utc)
    manifest = tmp_path / "evidence-manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "generated_at": now.isoformat(),
                "environment": "staging",
                "application_version": "0.2.0",
                "commit": "c" * 40,
                "evidence": [
                    {
                        "check_id": "configuration",
                        "title": "Configuration validation",
                        "status": "blocked",
                        "executed_at": (now - timedelta(hours=2)).isoformat(),
                        "expires_at": (now - timedelta(hours=1)).isoformat(),
                        "environment": "production",
                        "application_version": "0.2.0",
                        "tool": "validator",
                        "tool_version": "1",
                        "command_reference": "make readiness-evidence",
                        "reviewer": "automation:local",
                    },
                    {
                        "check_id": "migrations",
                        "title": "Migration validation",
                        "status": "blocked",
                        "executed_at": (now - timedelta(hours=2)).isoformat(),
                        "expires_at": (now - timedelta(hours=1)).isoformat(),
                        "environment": "staging",
                        "application_version": "0.2.0",
                        "tool": "validator",
                        "tool_version": "1",
                        "command_reference": "make readiness-evidence",
                        "reviewer": "automation:local",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )

    result = validate_evidence_manifest(
        manifest, environment="staging", application_version="0.2.0", now=now
    )

    assert result.errors == [
        "environment_mismatch:configuration",
        "expired:migrations",
    ]
    assert result.valid_checks == {}
