"""Evidence-based production readiness evaluation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Literal

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cyberaudit.config import Settings
from cyberaudit.hardening_models import (
    ProductionReadinessApproval,
    ProductionReadinessEvidence,
)
from cyberaudit.readiness_evidence import validate_evidence_manifest
from cyberaudit.rls import require_tenant_context

ReadinessState = Literal["blocked", "incomplete", "candidate", "approved"]

MANDATORY_CHECKS = (
    "configuration",
    "oidc_keycloak",
    "oidc_second_provider",
    "webauthn",
    "rls",
    "cross_tenant_tests",
    "dlq",
    "secret_provider",
    "object_storage",
    "docker_runner",
    "kubernetes_runner",
    "backup",
    "restore",
    "ha",
    "dr",
    "sbom",
    "signing",
    "provenance",
    "vulnerabilities",
    "coverage",
    "migrations",
    "release_validation",
    "upgrade",
    "rollback",
    "external_assessment",
)


@dataclass(frozen=True)
class ReadinessCheck:
    code: str
    status: str
    summary: str
    evidence_references: tuple[str, ...]
    observed_at: datetime | None
    expires_at: datetime | None


class ProductionReadinessGate:
    def __init__(self, settings: Settings, application_version: str = "0.2.0") -> None:
        self.settings = settings
        self.application_version = application_version

    @staticmethod
    def _utc(value: datetime) -> datetime:
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)

    async def evaluate(
        self, db: AsyncSession, organization_id: str, environment: str
    ) -> dict[str, Any]:
        await require_tenant_context(db, organization_id)
        now = datetime.now(timezone.utc)
        records = list(
            (
                await db.scalars(
                    select(ProductionReadinessEvidence).where(
                        ProductionReadinessEvidence.organization_id == organization_id,
                        ProductionReadinessEvidence.environment == environment,
                    )
                )
            ).all()
        )
        by_code = {record.check_code: record for record in records}
        manifest_checks = None
        manifest_errors: list[str] = []
        manifest_checksum: str | None = None
        if self.settings.readiness_evidence_manifest is not None:
            try:
                validation = validate_evidence_manifest(
                    self.settings.readiness_evidence_manifest,
                    environment=environment,
                    application_version=self.application_version,
                    now=now,
                )
                manifest_checks = validation.valid_checks
                manifest_errors = validation.errors
                manifest_checksum = validation.manifest_checksum
            except (OSError, ValueError):
                manifest_checks = {}
                manifest_errors = ["manifest_unavailable_or_invalid"]
        checks: list[ReadinessCheck] = []
        blockers: list[str] = []
        missing = 0
        for code in MANDATORY_CHECKS:
            record = by_code.get(code)
            if not record:
                missing += 1
                blockers.append(code)
                checks.append(
                    ReadinessCheck(code, "missing", "No evidence recorded", (), None, None)
                )
                continue
            expired = record.expires_at is not None and self._utc(record.expires_at) <= now
            status = "expired" if expired else record.status
            if status == "passed" and manifest_checks is not None:
                external = manifest_checks.get(code)
                if external is None:
                    status = "external_evidence_missing"
                elif external.status != "passed":
                    status = f"external_evidence_{external.status}"
            if status != "passed":
                blockers.append(code)
            checks.append(
                ReadinessCheck(
                    code,
                    status,
                    record.summary,
                    tuple(record.evidence_references),
                    record.observed_at,
                    record.expires_at,
                )
            )

        if blockers:
            state: ReadinessState = "incomplete" if missing == len(blockers) else "blocked"
        else:
            state = "candidate"
            approval = await db.scalar(
                select(ProductionReadinessApproval)
                .where(
                    ProductionReadinessApproval.organization_id == organization_id,
                    ProductionReadinessApproval.environment == environment,
                    ProductionReadinessApproval.status == "approved",
                    ProductionReadinessApproval.decision == "approved",
                )
                .order_by(ProductionReadinessApproval.reviewed_at.desc())
            )
            if approval and approval.reviewed_by and approval.reviewed_at:
                state = "approved"

        return {
            "state": state,
            "checks": [
                {
                    "code": check.code,
                    "status": check.status,
                    "summary": check.summary,
                    "evidence_references": list(check.evidence_references),
                    "observed_at": check.observed_at,
                    "expires_at": check.expires_at,
                }
                for check in checks
            ],
            "blockers": blockers,
            "evaluated_at": now,
            "environment": environment,
            "application_version": self.application_version,
            "formal_approval_required": state != "approved",
            "evidence_manifest": {
                "configured": self.settings.readiness_evidence_manifest is not None,
                "checksum": manifest_checksum,
                "errors": manifest_errors,
            },
        }
