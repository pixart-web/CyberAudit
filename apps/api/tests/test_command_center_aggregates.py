"""Phase 10.4.1 Command Center finalization: the four new cross-domain

aggregates (open incidents, active engagements, failing controls,
high-risk identities) must each be scoped to the caller's own tenant,
never counting another tenant's rows.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cyberaudit.db import get_db
from cyberaudit.domain_expansion_models import ExternalIdentity, IdentityProvider
from cyberaudit.enterprise_models import Incident, UnifiedControl
from cyberaudit.main import app
from cyberaudit.models import Engagement, EngagementMode, Organization, Permission, Role, User
from cyberaudit.security import current_user

ALL_PERMISSIONS = ["risk.read"]


async def _permission(db: AsyncSession, code: str) -> Permission:
    existing = await db.scalar(select(Permission).where(Permission.code == code))
    if existing:
        return existing
    permission = Permission(code=code, description=code)
    db.add(permission)
    await db.flush()
    return permission


async def _tenant(db: AsyncSession, suffix: str) -> tuple[Organization, User]:
    organization = Organization(name=f"CC Tenant {suffix}", slug=f"cc-tenant-{suffix}")
    db.add(organization)
    await db.flush()
    role = Role(
        name=f"CCOperator-{suffix}",
        permissions=[await _permission(db, code) for code in ALL_PERMISSIONS],
    )
    db.add(role)
    user = User(
        organization_id=organization.id,
        name=f"CC Operator {suffix}",
        email=f"cc-operator-{suffix}@example.invalid",
        password_hash="not-used",  # noqa: S106
        status="active",
    )
    user.roles = [role]
    db.add(user)
    await db.flush()
    return organization, user


@pytest.mark.asyncio
async def test_command_center_cross_domain_aggregates_are_tenant_scoped(db: AsyncSession):
    org_a, user_a = await _tenant(db, "a")
    org_b, _ = await _tenant(db, "b")

    # Tenant B has an open incident, an active engagement, a failing
    # control, and a high-risk identity -- none of which should ever
    # appear in tenant A's command center counts.
    db.add(Incident(organization_id=org_b.id, reference="INC-B", title="t", status="open"))
    db.add(
        Engagement(
            organization_id=org_b.id,
            client_id="client-b",
            name="Engagement B",
            code="ENG-B",
            mode=EngagementMode.CLIENT,
            status="active",
        )
    )
    db.add(
        UnifiedControl(
            organization_id=org_b.id,
            code="CTL-B",
            title="Control B",
            description="test",
            domain="access",
            implementation_status="not_implemented",
        )
    )
    provider_b = IdentityProvider(
        organization_id=org_b.id,
        connector_id="connector-b",
        provider_type="active_directory",
        name="AD-B",
        tenant_identifier="tenant-b",
    )
    db.add(provider_b)
    await db.flush()
    db.add(
        ExternalIdentity(
            organization_id=org_b.id,
            provider_id=provider_b.id,
            external_id="ext-b",
            identity_type="user",
            username="user-b",
            display_name="User B",
            risk_score=95,
        )
    )
    await db.flush()

    async def override_db() -> AsyncIterator[AsyncSession]:
        yield db

    async def override_user() -> User:
        return user_a

    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[current_user] = override_user
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
            base_url="http://testserver",
        ) as client:
            response = await client.get("/api/v1/command-center")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    body = response.json()
    assert body["open_incidents"] == 0
    assert body["active_engagements"] == 0
    assert body["failing_controls"] == 0
    assert body["high_risk_identities"] == 0
