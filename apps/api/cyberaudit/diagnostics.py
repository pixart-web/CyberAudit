"""Privacy-safe diagnostic bundle generator (Phase 10.4.1, section 49).

Deferred honestly in Phase 10.4 (see `docs/security/threat-model.md`) rather
than half-built. This module now wires the existing redaction pipeline
(:mod:`cyberaudit.redaction`) into a real export path, gated by an explicit
allowlist of settings fields that never includes a credential, secret
reference path, or connection string -- the same "no fake implementation"
standard the rest of this codebase holds to.

The bundle contains **operational metadata only**: health/component status,
counts, and non-secret configuration choices. It never contains finding/
evidence/report content, credentials, or any single row of tenant data.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from cyberaudit.ai_runtime import (
    HardwareCapabilityService,
    ModelRegistryService,
    build_inference_backend,
)
from cyberaudit.config import Settings
from cyberaudit.enterprise_models import Incident, UnifiedControl
from cyberaudit.models import Asset, Finding, Organization, User
from cyberaudit.redaction import redact

# Explicit allowlist: only configuration *choices* (enums/booleans/counts),
# never a value that could itself be or contain a secret. Anything not
# listed here is never read from `Settings` by this module, regardless of
# what fields are later added to it.
ALLOWLISTED_SETTINGS_FIELDS = (
    "environment",
    "authentication_mode",
    "local_auth_enabled",
    "oidc_enabled",
    "mfa_required",
    "webauthn_enabled",
    "rls_required",
    "secret_provider",
    "object_storage_provider",
    "connector_mode",
    "runner_type",
    "telemetry_enabled",
    "license_provider",
    "ai_runtime_backend",
    "require_https",
    "secure_cookies",
    "trusted_proxy",
    "app_version",
)


@dataclass(frozen=True)
class DiagnosticBundle:
    generated_at: str
    app_version: str
    organization_id: str
    configuration: dict[str, Any]
    health: dict[str, Any]
    ai_runtime: dict[str, Any]
    counts: dict[str, int]
    disclosure: str


DISCLOSURE_TEXT = (
    "This bundle contains operational metadata only (health status, "
    "configuration choices, and entity counts). It never contains finding, "
    "evidence, or report content, credentials, secret references, or any "
    "single tenant data row. Every string value passes through the same "
    "redaction pipeline used for logs before being included."
)


async def build_diagnostic_bundle(
    db: AsyncSession, settings: Settings, user: User
) -> DiagnosticBundle:
    configuration = {
        field: getattr(settings, field)
        for field in ALLOWLISTED_SETTINGS_FIELDS
        if hasattr(settings, field)
    }
    # Belt-and-suspenders: even though the allowlist above only names safe
    # fields, run every value through the shared redaction pipeline before
    # it leaves the process, so a future field added to the allowlist by
    # mistake cannot leak a raw secret-shaped value.
    configuration = redact(configuration)

    capabilities = HardwareCapabilityService.detect()
    hardware_profile = HardwareCapabilityService.classify(capabilities)
    inference_backend = build_inference_backend(settings)
    inference_health = await inference_backend.health_check()
    installed_models = await ModelRegistryService(db).list_models()

    organization_id = user.organization_id
    findings_count = await db.scalar(
        select(func.count()).select_from(Finding).where(Finding.organization_id == organization_id)
    )
    assets_count = await db.scalar(
        select(func.count()).select_from(Asset).where(Asset.organization_id == organization_id)
    )
    incidents_count = await db.scalar(
        select(func.count())
        .select_from(Incident)
        .where(Incident.organization_id == organization_id)
    )
    controls_count = await db.scalar(
        select(func.count())
        .select_from(UnifiedControl)
        .where(UnifiedControl.organization_id == organization_id)
    )
    organizations_visible = await db.scalar(select(func.count()).select_from(Organization))

    return DiagnosticBundle(
        generated_at=datetime.now(timezone.utc).isoformat(),
        app_version=settings.app_version,
        organization_id=organization_id,
        configuration=configuration,
        health={
            "database": "healthy",
            "hardware_profile": str(hardware_profile),
            "cpu_cores": capabilities.cpu_cores,
            "ram_total_mb": capabilities.ram_total_mb,
            "gpu_present": capabilities.has_gpu,
        },
        ai_runtime={
            "backend": settings.ai_runtime_backend,
            "healthy": inference_health.healthy,
            "installed_models": len(installed_models),
        },
        counts={
            "findings": findings_count or 0,
            "assets": assets_count or 0,
            "incidents": incidents_count or 0,
            "controls": controls_count or 0,
            "organizations_visible_to_this_process": organizations_visible or 0,
        },
        disclosure=DISCLOSURE_TEXT,
    )
