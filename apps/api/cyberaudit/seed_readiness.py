"""Idempotent synthetic identity configuration for the readiness laboratory."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from sqlalchemy import select

from cyberaudit.db import SessionLocal
from cyberaudit.hardening_models import AuthenticationProvider, ExternalGroupRoleMapping
from cyberaudit.models import Organization, Role, User

ISSUER = "https://idp.localhost:18444/realms/cyberaudit-readiness"
GROUP_ROLE_MAPPING = {
    "CyberAudit-Viewer": "Client",
    "CyberAudit-Analyst": "Reviewer",
    "CyberAudit-Admin": "Auditor",
}


async def seed() -> None:
    async with SessionLocal() as db:
        organization = await db.scalar(
            select(Organization).where(Organization.slug == "cyberaudit-demo")
        )
        administrator = await db.scalar(select(User).where(User.email == "admin@cyberaudit.local"))
        if not organization or not administrator:
            raise RuntimeError("Run the base seed before the readiness seed")
        provider = await db.scalar(
            select(AuthenticationProvider).where(
                AuthenticationProvider.organization_id == organization.id,
                AuthenticationProvider.code == "readiness-keycloak",
            )
        )
        if not provider:
            provider = AuthenticationProvider(
                organization_id=organization.id,
                code="readiness-keycloak",
                name="Keycloak readiness laboratory",
                issuer=ISSUER,
                client_id="cyberaudit-web",
                scopes=["openid", "profile", "email", "groups"],
                allowed_domains=["example.test"],
                jit_enabled=True,
                jit_requires_approval=False,
                enabled=True,
                configuration={"synthetic_data_only": True, "pkce": "S256"},
                created_by=administrator.id,
            )
            db.add(provider)
            await db.flush()
        else:
            provider.issuer = ISSUER
            provider.enabled = True
            provider.jit_enabled = True
            provider.jit_requires_approval = False

        for external_group, role_name in GROUP_ROLE_MAPPING.items():
            role = await db.scalar(select(Role).where(Role.name == role_name))
            if not role:
                raise RuntimeError(f"Missing base role: {role_name}")
            mapping = await db.scalar(
                select(ExternalGroupRoleMapping).where(
                    ExternalGroupRoleMapping.organization_id == organization.id,
                    ExternalGroupRoleMapping.provider_id == provider.id,
                    ExternalGroupRoleMapping.external_group == external_group,
                    ExternalGroupRoleMapping.role_id == role.id,
                )
            )
            if not mapping:
                db.add(
                    ExternalGroupRoleMapping(
                        organization_id=organization.id,
                        provider_id=provider.id,
                        external_group=external_group,
                        role_id=role.id,
                        enabled=True,
                        approved_by=administrator.id,
                        approved_at=datetime.now(timezone.utc),
                    )
                )
        await db.commit()
        print("Readiness Keycloak provider and bounded role mappings seeded.")


if __name__ == "__main__":
    asyncio.run(seed())
