"""Deterministic, read-only services for enterprise domain expansion."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

SECRET_KEYS = {
    "access_token",
    "api_key",
    "authorization",
    "client_secret",
    "credential",
    "password",
    "private_key",
    "refresh_token",
    "secret",
    "token",
}
SECRET_REFERENCE_SCHEMES = (
    "vault://",
    "aws-secrets://",
    "azure-key-vault://",
    "gcp-secret://",
    "development://demo-",
)
CONNECTOR_TYPES = {
    "active_directory",
    "entra_id",
    "microsoft_365",
    "google_workspace",
    "aws",
    "azure",
    "gcp",
    "kubernetes",
    "container_runtime",
    "endpoint",
    "mobile",
}
ZERO_TRUST_DIMENSIONS = (
    "identity",
    "device",
    "session",
    "application",
    "network",
    "workload",
    "data",
    "control",
)
ZERO_TRUST_WEIGHTS = {
    "identity": 1.25,
    "device": 1.1,
    "session": 1.0,
    "application": 1.0,
    "network": 0.9,
    "workload": 0.9,
    "data": 1.0,
    "control": 0.85,
}
ZeroTrustStatus = Literal["strong", "moderate", "weak", "insufficient_evidence"]
_INLINE_SECRET = re.compile(
    r"(?i)\b(password|token|secret|api[_-]?key|authorization)\b\s*[:=]\s*[^,\s;]+"
)


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ConnectorConfiguration(StrictModel):
    connector_type: str
    provider: str = Field(min_length=2, max_length=80)
    read_only: Literal[True] = True
    requested_permissions: list[str] = Field(default_factory=list, max_length=100)
    capabilities: list[str] = Field(default_factory=list, max_length=100)
    retention_days: int = Field(default=90, ge=1, le=3650)

    @field_validator("connector_type")
    @classmethod
    def known_connector(cls, value: str) -> str:
        if value not in CONNECTOR_TYPES:
            raise ValueError("Unsupported connector type")
        return value

    @field_validator("requested_permissions", "capabilities")
    @classmethod
    def safe_identifiers(cls, values: list[str]) -> list[str]:
        pattern = re.compile(r"^[a-z0-9_.:/-]{1,160}$")
        if len(values) != len(set(values)) or any(not pattern.fullmatch(value) for value in values):
            raise ValueError("Values must be unique allowlisted identifiers")
        return values


class ZeroTrustEvaluationRequest(StrictModel):
    subject_type: Literal[
        "organization", "identity", "device", "application", "workload", "resource", "session"
    ]
    subject_id: str | None = Field(default=None, max_length=36)
    facts: dict[str, dict[str, bool | float | None]]
    evidence_ids: list[str] = Field(default_factory=list, max_length=500)

    @field_validator("facts")
    @classmethod
    def supported_dimensions(
        cls, value: dict[str, dict[str, bool | float | None]]
    ) -> dict[str, dict[str, bool | float | None]]:
        unsupported = set(value) - set(ZERO_TRUST_DIMENSIONS)
        if unsupported:
            raise ValueError(f"Unsupported Zero Trust dimensions: {sorted(unsupported)}")
        return value


class DimensionResult(StrictModel):
    dimension: str
    score: float
    status: Literal["strong", "moderate", "weak", "insufficient_evidence"]
    weight: float
    confidence: float
    factors: list[dict[str, Any]]
    unknown_factors: list[str]
    evidence_ids: list[str]


class ZeroTrustResult(StrictModel):
    score: float
    status: Literal["strong", "moderate", "weak", "insufficient_evidence"]
    confidence: float
    dimensions: list[DimensionResult]
    factors: list[dict[str, Any]]
    unknown_factors: list[str]
    recommendations: list[str]
    control_mappings: list[str]
    evaluated_at: datetime
    algorithm_version: str = "zero-trust-1.0.0"


def validate_secret_reference(reference: str) -> str:
    """Accept only secret-manager references; never accept credential material."""
    if len(reference) > 500 or not reference.startswith(SECRET_REFERENCE_SCHEMES):
        raise ValueError("Credential must be a supported secret-manager reference")
    if any(character.isspace() for character in reference):
        raise ValueError("Credential reference cannot contain whitespace")
    return reference


def secret_reference_fingerprint(reference: str) -> str:
    validate_secret_reference(reference)
    return hashlib.sha256(reference.encode()).hexdigest()


def sanitize_external_data(value: Any) -> Any:
    """Recursively redact credentials and keep external text non-executable."""
    if isinstance(value, dict):
        return {
            str(key)[:200]: (
                "[REDACTED]"
                if str(key).lower().replace("-", "_") in SECRET_KEYS
                else sanitize_external_data(item)
            )
            for key, item in list(value.items())[:1000]
        }
    if isinstance(value, list):
        return [sanitize_external_data(item) for item in value[:1000]]
    if isinstance(value, str):
        return _INLINE_SECRET.sub(r"\1=[REDACTED]", value.replace("\x00", ""))[:10_000]
    if isinstance(value, (bool, int, float)) or value is None:
        return value
    return str(value)[:1000]


def stable_snapshot(value: Any) -> tuple[dict[str, Any], str]:
    sanitized = sanitize_external_data(value)
    if not isinstance(sanitized, dict):
        raise ValueError("Configuration snapshots must be objects")
    canonical = json.dumps(sanitized, sort_keys=True, separators=(",", ":"))
    return sanitized, hashlib.sha256(canonical.encode()).hexdigest()


@dataclass(frozen=True)
class ChangeResult:
    changed: bool
    before_hash: str | None
    after_hash: str
    changed_fields: list[str]
    fingerprint: str


def detect_change(
    organization_id: str,
    domain: str,
    subject_external_id: str,
    current: dict[str, Any],
    previous: dict[str, Any] | None = None,
) -> ChangeResult:
    sanitized, after_hash = stable_snapshot(current)
    before_sanitized: dict[str, Any] = {}
    before_hash = None
    if previous is not None:
        before_sanitized, before_hash = stable_snapshot(previous)
    changed_fields = sorted(
        key
        for key in set(before_sanitized) | set(sanitized)
        if before_sanitized.get(key) != sanitized.get(key)
    )
    identity = "|".join(
        [organization_id, domain, subject_external_id, before_hash or "new", after_hash]
    )
    return ChangeResult(
        changed=previous is None or before_hash != after_hash,
        before_hash=before_hash,
        after_hash=after_hash,
        changed_fields=changed_fields,
        fingerprint=hashlib.sha256(identity.encode()).hexdigest(),
    )


class ZeroTrustEngine:
    """Explainable assessment. Missing telemetry reduces confidence, never score."""

    @staticmethod
    def _status(score: float, confidence: float) -> ZeroTrustStatus:
        if confidence < 0.35:
            return "insufficient_evidence"
        if score >= 80:
            return "strong"
        if score >= 55:
            return "moderate"
        return "weak"

    def evaluate(self, request: ZeroTrustEvaluationRequest) -> ZeroTrustResult:
        dimensions: list[DimensionResult] = []
        aggregate_factors: list[dict[str, Any]] = []
        unknown: list[str] = []
        weighted_score = 0.0
        observed_weight = 0.0
        total_weight = sum(ZERO_TRUST_WEIGHTS.values())

        for dimension in ZERO_TRUST_DIMENSIONS:
            facts = request.facts.get(dimension, {})
            known = {key: value for key, value in facts.items() if value is not None}
            dimension_unknown = sorted(key for key, value in facts.items() if value is None)
            if not facts:
                dimension_unknown = ["telemetry_missing"]
            factor_rows: list[dict[str, Any]] = []
            points: list[float] = []
            for key, value in sorted(known.items()):
                score = (
                    100.0
                    if value is True
                    else 0.0 if value is False else max(0.0, min(100.0, float(value)))
                )
                points.append(score)
                factor_rows.append({"factor": key, "observed": value, "score": score})
            score = round(sum(points) / len(points), 2) if points else 0.0
            confidence = round(len(known) / max(len(facts), 1), 2) if facts else 0.0
            weight = ZERO_TRUST_WEIGHTS[dimension]
            if known:
                weighted_score += score * weight
                observed_weight += weight
            qualified_unknown = [f"{dimension}.{key}" for key in dimension_unknown]
            unknown.extend(qualified_unknown)
            dimensions.append(
                DimensionResult(
                    dimension=dimension,
                    score=score,
                    status=self._status(score, confidence),
                    weight=weight,
                    confidence=confidence,
                    factors=factor_rows,
                    unknown_factors=qualified_unknown,
                    evidence_ids=request.evidence_ids,
                )
            )
            aggregate_factors.extend({"dimension": dimension, **factor} for factor in factor_rows)

        score = round(weighted_score / observed_weight, 2) if observed_weight else 0.0
        confidence = round(observed_weight / total_weight, 2)
        weak_dimensions = [
            item.dimension
            for item in dimensions
            if item.status in {"weak", "insufficient_evidence"}
        ]
        recommendations = [
            f"Increase verified telemetry and control coverage for {dimension}."
            for dimension in weak_dimensions
        ]
        return ZeroTrustResult(
            score=score,
            status=self._status(score, confidence),
            confidence=confidence,
            dimensions=dimensions,
            factors=aggregate_factors,
            unknown_factors=unknown,
            recommendations=recommendations,
            control_mappings=["NIST-ZTA", "CISA-ZTMM"],
            evaluated_at=datetime.now(timezone.utc),
        )


def identity_risk_factors(
    *,
    privileged: bool,
    mfa_enforced: str,
    enabled: bool,
    stale_days: int | None,
    guest: bool,
    owner: str | None,
) -> tuple[float, list[str]]:
    factors: list[tuple[float, str]] = []
    if privileged:
        factors.append((25, "privileged_identity"))
    if mfa_enforced == "false":
        factors.append((35, "mfa_not_enforced"))
    elif mfa_enforced == "unknown":
        factors.append((10, "mfa_state_unknown"))
    if enabled and stale_days is not None and stale_days > 90:
        factors.append((20, "enabled_stale_identity"))
    if guest:
        factors.append((10, "guest_identity"))
    if not owner:
        factors.append((15, "owner_missing"))
    return min(100.0, sum(score for score, _ in factors)), [reason for _, reason in factors]


def cloud_risk_factors(
    *,
    public_exposure: bool,
    criticality: str,
    encryption: str,
    logging: str,
    wildcard_permissions: bool,
) -> tuple[float, list[str]]:
    factors: list[tuple[float, str]] = []
    if public_exposure:
        factors.append((30, "public_exposure"))
    if criticality == "critical":
        factors.append((20, "critical_resource"))
    if encryption == "false":
        factors.append((25, "encryption_disabled"))
    elif encryption == "unknown":
        factors.append((8, "encryption_unknown"))
    if logging == "false":
        factors.append((15, "logging_disabled"))
    if wildcard_permissions:
        factors.append((30, "wildcard_permissions"))
    return min(100.0, sum(score for score, _ in factors)), [reason for _, reason in factors]
