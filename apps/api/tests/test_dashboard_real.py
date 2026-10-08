"""The dashboard must never show invented numbers."""

from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cyberaudit.admin_api import ensure_rbac
from cyberaudit.db import get_db
from cyberaudit.enterprise_models import Incident
from cyberaudit.main import app
from cyberaudit.models import (
    Client,
    Criticality,
    Engagement,
    EngagementMode,
    Finding,
    Organization,
    Role,
    User,
)
from cyberaudit.security import current_user


async def _admin(db: AsyncSession, slug: str) -> User:
    org = Organization(name=slug, slug=slug)
    db.add(org)
    await db.flush()
    role = await db.scalar(select(Role).where(Role.name == "Administrator"))
    user = User(
        organization_id=org.id,
        name="U",
        email=f"u@{slug}.example.com",
        password_hash="not-a-real-hash",  # noqa: S106
        roles=[role],
    )
    db.add(user)
    await db.flush()
    return user


async def _get(db: AsyncSession, user: User):
    async def override_db() -> AsyncIterator[AsyncSession]:
        yield db

    async def override_user() -> User:
        return await db.get(User, user.id, populate_existing=True)  # type: ignore[return-value]

    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[current_user] = override_user
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
            base_url="http://testserver",
        ) as c:
            return (await c.get("/api/v1/dashboard")).json()
    finally:
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_empty_tenant_shows_no_invented_values(db: AsyncSession):
    await ensure_rbac(db)
    user = await _admin(db, "empty")
    await db.commit()
    body = await _get(db, user)
    assert body["metrics"]["posture"] is None and body["metrics"]["retest_rate"] is None
    assert body["top_risks"] == [] and body["incidents"] == []
    assert body["metrics"]["assets"] == 0 and body["metrics"]["findings"] == 0


@pytest.mark.asyncio
async def test_dashboard_reflects_only_own_tenant_records(db: AsyncSession):
    await ensure_rbac(db)
    a, b = await _admin(db, "a"), await _admin(db, "b")
    client = Client(organization_id=a.organization_id, name="C")
    db.add(client)
    await db.flush()
    eng = Engagement(
        organization_id=a.organization_id,
        client_id=client.id,
        name="E",
        code="E-A",
        mode=EngagementMode.CLIENT,
        owner_id=a.id,
    )
    db.add(eng)
    await db.flush()
    db.add(
        Finding(
            organization_id=a.organization_id,
            engagement_id=eng.id,
            job_id="j",
            title="Real finding A",
            description="d",
            category="c",
            technical_severity=Criticality.CRITICAL,
            confidence="high",
            affected_component="srv-a",
            technical_impact="t",
            business_impact="b",
            remediation_summary="r",
            validation_steps=[],
            source_adapter="x",
            fingerprint="fp-a",
        )
    )
    db.add(
        Incident(
            organization_id=a.organization_id,
            reference="INC-A",
            title="Incident A",
            severity="high",
            status="open",
        )
    )
    await db.commit()
    mine, theirs = await _get(db, a), await _get(db, b)
    assert [r["title"] for r in mine["top_risks"]] == ["Real finding A"]
    assert [i["title"] for i in mine["incidents"]] == ["Incident A"]
    assert theirs["top_risks"] == [] and theirs["incidents"] == []
    assert "Autenticação sem MFA" not in str(mine) + str(theirs)
