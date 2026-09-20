"""Validation of externally collected production-readiness evidence."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

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


class EvidenceItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    check_id: str = Field(pattern=r"^[a-z][a-z0-9_]{1,80}$")
    title: str = Field(min_length=3, max_length=200)
    status: Literal["passed", "failed", "blocked"]
    executed_at: datetime
    expires_at: datetime | None = None
    environment: str = Field(min_length=2, max_length=80)
    application_version: str = Field(min_length=1, max_length=80)
    tool: str = Field(min_length=1, max_length=100)
    tool_version: str = Field(min_length=1, max_length=200)
    command_reference: str = Field(min_length=1, max_length=300)
    artifact_path: str | None = Field(default=None, max_length=500)
    checksum: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    reviewer: str = Field(min_length=1, max_length=200)
    notes: str = Field(default="", max_length=1000)

    @field_validator("executed_at", "expires_at")
    @classmethod
    def timezone_required(cls, value: datetime | None) -> datetime | None:
        if value is not None and value.tzinfo is None:
            raise ValueError("Evidence timestamps must include a timezone")
        return value


class EvidenceManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"]
    generated_at: datetime
    environment: str
    application_version: str
    commit: str = Field(pattern=r"^[a-f0-9]{40}$")
    evidence: list[EvidenceItem]

    @field_validator("generated_at")
    @classmethod
    def generated_at_timezone_required(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("Manifest timestamp must include a timezone")
        return value


class EvidenceManifestValidation(BaseModel):
    valid_checks: dict[str, EvidenceItem]
    errors: list[str]
    manifest_checksum: str


def validate_evidence_manifest(
    manifest_path: Path,
    *,
    environment: str,
    application_version: str,
    now: datetime | None = None,
) -> EvidenceManifestValidation:
    current = now or datetime.now(timezone.utc)
    raw = manifest_path.read_bytes()
    manifest = EvidenceManifest.model_validate_json(raw)
    errors: list[str] = []
    valid: dict[str, EvidenceItem] = {}
    seen: set[str] = set()
    if manifest.environment != environment:
        errors.append("manifest_environment_mismatch")
    if manifest.application_version != application_version:
        errors.append("manifest_application_version_mismatch")
    if manifest.generated_at > current:
        errors.append("manifest_generated_in_future")

    root = manifest_path.resolve().parent
    for item in manifest.evidence:
        if item.check_id in seen:
            errors.append(f"duplicate_check:{item.check_id}")
            continue
        seen.add(item.check_id)
        if item.environment != environment:
            errors.append(f"environment_mismatch:{item.check_id}")
            continue
        if item.application_version != application_version:
            errors.append(f"version_mismatch:{item.check_id}")
            continue
        if item.executed_at > current:
            errors.append(f"executed_in_future:{item.check_id}")
            continue
        if item.expires_at is not None and item.expires_at <= current:
            errors.append(f"expired:{item.check_id}")
            continue
        if item.status == "passed":
            if item.check_id in HUMAN_REVIEW_REQUIRED and item.reviewer.startswith("automation:"):
                errors.append(f"human_review_required:{item.check_id}")
                continue
            if not item.artifact_path or not item.checksum:
                errors.append(f"artifact_required:{item.check_id}")
                continue
            candidate = (root / item.artifact_path).resolve()
            if root != candidate and root not in candidate.parents:
                errors.append(f"unsafe_artifact_path:{item.check_id}")
                continue
            if not candidate.is_file():
                errors.append(f"artifact_missing:{item.check_id}")
                continue
            if candidate.stat().st_size == 0:
                errors.append(f"artifact_empty:{item.check_id}")
                continue
            digest = hashlib.sha256(candidate.read_bytes()).hexdigest()
            if digest != item.checksum:
                errors.append(f"checksum_mismatch:{item.check_id}")
                continue
        valid[item.check_id] = item
    return EvidenceManifestValidation(
        valid_checks=valid,
        errors=errors,
        manifest_checksum=hashlib.sha256(raw).hexdigest(),
    )
