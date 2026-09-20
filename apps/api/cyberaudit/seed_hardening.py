"""Deterministic Phase 10 operational defaults; safe to run repeatedly."""

from __future__ import annotations

import asyncio

from sqlalchemy import select

from cyberaudit.db import SessionLocal
from cyberaudit.hardening_models import (
    AuthenticationProvider,
    FeatureFlag,
    LicenseRecord,
    RetentionPolicy,
    ServiceLevelObjective,
    TelemetryPreference,
)
from cyberaudit.models import Organization, Permission, Role, User
from cyberaudit.product_services import LicenseService

HARDENING_PERMISSIONS = [
    "authentication_providers.read",
    "authentication_providers.manage",
    "sessions.read",
    "sessions.manage",
    "mfa.manage",
    "feature_flags.read",
    "feature_flags.manage",
    "license.read",
    "license.manage",
    "telemetry.read",
    "telemetry.manage",
    "operations.read",
    "backups.read",
    "backups.manage",
    "restores.read",
    "restores.manage",
    "dead_letters.read",
    "dead_letters.manage",
    "production_readiness.manage",
]


async def seed() -> None:
    async with SessionLocal() as db:
        organization = await db.scalar(
            select(Organization).where(Organization.slug == "cyberaudit-demo")
        )
        administrator = await db.scalar(select(User).where(User.email == "admin@cyberaudit.local"))
        role = await db.scalar(select(Role).where(Role.name == "Administrator"))
        if not organization or not administrator or not role:
            raise RuntimeError("Run the base seed before seed-hardening")

        for code in HARDENING_PERMISSIONS:
            permission = await db.scalar(select(Permission).where(Permission.code == code))
            if not permission:
                permission = Permission(code=code, description=code.replace(".", " ").title())
                db.add(permission)
                await db.flush()
            if permission not in role.permissions:
                role.permissions.append(permission)

        if not await db.scalar(
            select(AuthenticationProvider).where(
                AuthenticationProvider.organization_id == organization.id,
                AuthenticationProvider.code == "demo-oidc",
            )
        ):
            db.add(
                AuthenticationProvider(
                    organization_id=organization.id,
                    code="demo-oidc",
                    name="OIDC empresarial (não configurado)",
                    issuer="https://identity.example.invalid",
                    client_id="cyberaudit-demo",
                    scopes=["openid", "profile", "email", "groups"],
                    allowed_domains=["example.invalid"],
                    enabled=False,
                    jit_enabled=False,
                    created_by=administrator.id,
                    configuration={"status": "requires_operator_configuration"},
                )
            )

        for code, description in {
            "enterprise_sso": "Ativa SSO empresarial após validação do fornecedor.",
            "live_connectors": "Ativa conectores read-only depois dos testes contratuais.",
            "external_runners": "Ativa runners efémeros após health checks.",
            "anonymous_telemetry": "Ativa telemetria mínima apenas com consentimento.",
            "dead_letter_replay": "Permite replay manual após step-up e revalidação.",
        }.items():
            if not await db.scalar(
                select(FeatureFlag).where(
                    FeatureFlag.organization_id == organization.id,
                    FeatureFlag.code == code,
                    FeatureFlag.environment == "development",
                )
            ):
                db.add(
                    FeatureFlag(
                        organization_id=organization.id,
                        code=code,
                        description=description,
                        environment="development",
                        enabled=False,
                        created_by=administrator.id,
                    )
                )

        if not await db.scalar(
            select(LicenseRecord).where(LicenseRecord.organization_id == organization.id)
        ):
            db.add(LicenseService.community(organization.id))
        if not await db.scalar(
            select(TelemetryPreference).where(
                TelemetryPreference.organization_id == organization.id
            )
        ):
            db.add(TelemetryPreference(organization_id=organization.id, enabled=False))

        for category, active, archive, deletion in [
            ("audit_logs", 365, 2555, None),
            ("evidence", 365, 1095, 2555),
            ("raw_results", 90, 365, 730),
            ("sessions", 30, None, 90),
        ]:
            if not await db.scalar(
                select(RetentionPolicy).where(
                    RetentionPolicy.organization_id == organization.id,
                    RetentionPolicy.data_category == category,
                )
            ):
                db.add(
                    RetentionPolicy(
                        organization_id=organization.id,
                        data_category=category,
                        active_days=active,
                        archive_days=archive,
                        delete_after_days=deletion,
                        created_by=administrator.id,
                    )
                )

        for code, service, indicator, target in [
            ("api_availability", "api", "availability", 99.9),
            ("job_completion", "worker", "successful_completion", 99.0),
            ("policy_latency", "policy", "p95_latency_ms", 250.0),
        ]:
            if not await db.scalar(
                select(ServiceLevelObjective).where(
                    ServiceLevelObjective.organization_id == organization.id,
                    ServiceLevelObjective.code == code,
                )
            ):
                db.add(
                    ServiceLevelObjective(
                        organization_id=organization.id,
                        code=code,
                        service=service,
                        indicator=indicator,
                        target=target,
                        status="unmeasured",
                        owner="Platform Operations",
                    )
                )
        await db.commit()
        print("Phase 10 operational defaults seeded.")


if __name__ == "__main__":
    asyncio.run(seed())
