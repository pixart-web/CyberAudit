"""Phase 10.4.1 Risk Workspace: cross-tenant isolation for the new

Risk Register single-item GET (with embedded treatments), and the new
`?asset_id=` filters on the Risk Register list and Attack Paths list.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cyberaudit.db import get_db
from cyberaudit.enterprise_models import EnterpriseRisk, RiskTreatmentPlan
from cyberaudit.main import app
from cyberaudit.models import (
    Asset,
    Criticality,
    Engagement,
    EngagementMode,
    Organization,
    Permission,
    Role,
    User,
)
from cyberaudit.phase4_models import AttackPath
from cyberaudit.security import current_user

ALL_PERMISSIONS = ["enterprise_risks.read", "attack_paths.read", "assets.read"]


async def _permission(db: AsyncSession, code: str) -> Permission:
    existing = await db.scalar(select(Permission).where(Permission.code == code))
    if existing:
        return existing
    permission = Permission(code=code, description=code)
    db.add(permission)
    await db.flush()
    return permission


async def _tenant(db: AsyncSession, suffix: str) -> tuple[Organization, User]:
    organization = Organization(name=f"Risk Tenant {suffix}", slug=f"risk-tenant-{suffix}")
    db.add(organization)
    await db.flush()
    role = Role(
        name=f"RiskOperator-{suffix}",
        permissions=[await _permission(db, code) for code in ALL_PERMISSIONS],
    )
    db.add(role)
    user = User(
        organization_id=organization.id,
        name=f"Risk Operator {suffix}",
        email=f"risk-operator-{suffix}@example.invalid",
        password_hash="not-used",  # noqa: S106
        status="active",
    )
    user.roles = [role]
    db.add(user)
    await db.flush()
    return organization, user


async def _asset(db: AsyncSession, organization_id: str, suffix: str) -> Asset:
    engagement = Engagement(
        organization_id=organization_id,
        client_id=f"client-{suffix}",
        name=f"Engagement {suffix}",
        code=f"ENG-{suffix}",
        mode=EngagementMode.CLIENT,
    )
    db.add(engagement)
    await db.flush()
    asset = Asset(
        organization_id=organization_id,
        engagement_id=engagement.id,
        name=f"asset-{suffix}",
        asset_type="host",
        identifier=f"asset-{suffix}-1",
        criticality=Criticality.LOW,
    )
    db.add(asset)
    await db.flush()
    return asset


async def _request(db: AsyncSession, user: User, path: str) -> httpx.Response:
    async def override_db() -> AsyncIterator[AsyncSession]:
        yield db

    async def override_user() -> User:
        return user

    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[current_user] = override_user
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
            base_url="http://testserver",
        ) as client:
            return await client.get(path)
    finally:
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_risk_register_detail_and_treatments_are_tenant_scoped(db: AsyncSession):
    org_a, user_a = await _tenant(db, "risk-a")
    org_b, _ = await _tenant(db, "risk-b")
    risk_b = EnterpriseRisk(
        organization_id=org_b.id,
        reference="RISK-B-1",
        title="Tenant B risk",
        description="test",
        risk_type="cyber",
        category="test",
    )
    db.add(risk_b)
    await db.flush()
    db.add(
        RiskTreatmentPlan(
            organization_id=org_b.id,
            risk_id=risk_b.id,
            title="Mitigate",
            description="test",
            owner_id="user-b",
        )
    )
    await db.flush()

    response = await _request(db, user_a, f"/api/v1/grc/risks/{risk_b.id}")
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_risk_register_asset_id_filter_is_tenant_scoped(db: AsyncSession):
    org_a, user_a = await _tenant(db, "risk-filter-a")
    org_b, _ = await _tenant(db, "risk-filter-b")
    asset_b = await _asset(db, org_b.id, "risk-filter-b")
    db.add(
        EnterpriseRisk(
            organization_id=org_b.id,
            reference="RISK-B-2",
            title="Tenant B asset risk",
            description="test",
            risk_type="cyber",
            category="test",
            asset_id=asset_b.id,
        )
    )
    await db.flush()

    response = await _request(db, user_a, f"/api/v1/grc/risks?asset_id={asset_b.id}")
    assert response.status_code == 200
    assert response.json()["items"] == []


@pytest.mark.asyncio
async def test_attack_paths_asset_id_filter_is_tenant_scoped(db: AsyncSession):
    org_a, user_a = await _tenant(db, "path-a")
    org_b, _ = await _tenant(db, "path-b")
    entry_b = await _asset(db, org_b.id, "path-b-entry")
    target_b = await _asset(db, org_b.id, "path-b-target")
    db.add(
        AttackPath(
            organization_id=org_b.id,
            name="tenant b path",
            description="test",
            entry_asset_id=entry_b.id,
            target_asset_id=target_b.id,
            path_type="lateral_movement",
            severity="high",
            confidence=0.8,
            likelihood=0.5,
            impact=0.5,
            overall_risk=50,
            calculation_version="1.0.0",
        )
    )
    await db.flush()

    response = await _request(db, user_a, f"/api/v1/attack-paths?asset_id={entry_b.id}")
    assert response.status_code == 200
    assert response.json()["items"] == []
