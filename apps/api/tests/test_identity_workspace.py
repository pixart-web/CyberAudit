"""Phase 10.4.1 Identity Workspace: cross-tenant isolation for the new

`?identity_id=` filters (relationships, posture) and the new per-identity
risk endpoint, plus a correctness check for the stale-account bug fix
(the bulk /identity/risk endpoint always passed stale_days=None, so the
"stale account" factor could never fire).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cyberaudit.db import get_db
from cyberaudit.domain_expansion_models import (
    AuthenticationPosture,
    ExternalIdentity,
    IdentityProvider,
    IdentityRelationship,
)
from cyberaudit.main import app
from cyberaudit.models import Organization, Permission, Role, User
from cyberaudit.security import current_user

ALL_PERMISSIONS = ["identity.read", "identity.posture.read", "identity.risk.read"]


async def _permission(db: AsyncSession, code: str) -> Permission:
    existing = await db.scalar(select(Permission).where(Permission.code == code))
    if existing:
        return existing
    permission = Permission(code=code, description=code)
    db.add(permission)
    await db.flush()
    return permission


async def _tenant(db: AsyncSession, suffix: str) -> tuple[Organization, User]:
    organization = Organization(name=f"Identity Tenant {suffix}", slug=f"identity-tenant-{suffix}")
    db.add(organization)
    await db.flush()
    role = Role(
        name=f"IdentityOperator-{suffix}",
        permissions=[await _permission(db, code) for code in ALL_PERMISSIONS],
    )
    db.add(role)
    user = User(
        organization_id=organization.id,
        name=f"Identity Operator {suffix}",
        email=f"identity-operator-{suffix}@example.invalid",
        password_hash="not-used",  # noqa: S106
        status="active",
    )
    user.roles = [role]
    db.add(user)
    await db.flush()
    return organization, user


async def _identity(
    db: AsyncSession, organization_id: str, suffix: str, **overrides
) -> ExternalIdentity:
    provider = IdentityProvider(
        organization_id=organization_id,
        connector_id="connector-1",
        provider_type="active_directory",
        name=f"AD-{suffix}",
        tenant_identifier=f"tenant-{suffix}",
    )
    db.add(provider)
    await db.flush()
    defaults = dict(
        organization_id=organization_id,
        provider_id=provider.id,
        external_id=f"ext-{suffix}",
        identity_type="user",
        username=f"user-{suffix}",
        display_name=f"User {suffix}",
    )
    defaults.update(overrides)
    identity = ExternalIdentity(**defaults)
    db.add(identity)
    await db.flush()
    return identity


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
async def test_identity_risk_detail_is_tenant_scoped(db: AsyncSession):
    org_a, user_a = await _tenant(db, "risk-a")
    org_b, _ = await _tenant(db, "risk-b")
    identity_b = await _identity(db, org_b.id, "risk-b")

    response = await _request(db, user_a, f"/api/v1/identity/users/{identity_b.id}/risk")
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_identity_posture_and_relationship_filters_are_tenant_scoped(db: AsyncSession):
    org_a, user_a = await _tenant(db, "filter-a")
    org_b, _ = await _tenant(db, "filter-b")
    identity_b = await _identity(db, org_b.id, "filter-b")
    db.add(AuthenticationPosture(organization_id=org_b.id, identity_id=identity_b.id))
    db.add(
        IdentityRelationship(
            organization_id=org_b.id,
            relationship_type="member_of",
            source_type="identity",
            source_id=identity_b.id,
            target_type="group",
            target_id="group-b",
            source="test",
        )
    )
    await db.flush()

    posture = await _request(db, user_a, f"/api/v1/identity/posture?identity_id={identity_b.id}")
    relationships = await _request(
        db, user_a, f"/api/v1/identity/relationships?identity_id={identity_b.id}"
    )
    assert posture.status_code == 200 and posture.json()["items"] == []
    assert relationships.status_code == 200 and relationships.json()["items"] == []


@pytest.mark.asyncio
async def test_identity_risk_detects_a_genuinely_stale_privileged_account(db: AsyncSession):
    """The stale-account factor was dead code (stale_days was hardcoded to

    None at the one call site). This proves the per-identity risk endpoint
    now actually computes it from last_activity_at and scores accordingly.
    """
    organization, user = await _tenant(db, "stale")
    stale_identity = await _identity(
        db,
        organization.id,
        "stale-priv",
        privileged=True,
        enabled=True,
        mfa_state="true",
        owner="someone",
        last_activity_at=datetime.now(timezone.utc) - timedelta(days=200),
    )

    response = await _request(db, user, f"/api/v1/identity/users/{stale_identity.id}/risk")
    assert response.status_code == 200
    body = response.json()
    assert "enabled_stale_identity" in body["reasons"]
    assert "privileged_identity" in body["reasons"]


@pytest.mark.asyncio
async def test_identity_risk_handles_a_naive_last_activity_timestamp(db: AsyncSession):
    """SQLite (this dev/local database) does not persist tzinfo on a

    DateTime(timezone=True) column, so a value read back from a real
    request comes back naive even though it was written timezone-aware --
    this reproduces that exact shape (a naive datetime with no tzinfo,
    not one built with datetime.now(timezone.utc)) and proves the
    endpoint no longer raises "can't subtract offset-naive and
    offset-aware datetimes".
    """
    organization, user = await _tenant(db, "naive-ts")
    naive_stale_identity = await _identity(
        db,
        organization.id,
        "naive-stale",
        enabled=True,
        owner="someone",
        last_activity_at=datetime.now() - timedelta(days=200),  # noqa: DTZ005 -- deliberately naive
    )

    response = await _request(db, user, f"/api/v1/identity/users/{naive_stale_identity.id}/risk")
    assert response.status_code == 200
    assert "enabled_stale_identity" in response.json()["reasons"]


@pytest.mark.asyncio
async def test_identity_risk_does_not_flag_a_recently_active_account_as_stale(db: AsyncSession):
    organization, user = await _tenant(db, "fresh")
    fresh_identity = await _identity(
        db,
        organization.id,
        "fresh",
        enabled=True,
        owner="someone",
        last_activity_at=datetime.now(timezone.utc) - timedelta(days=1),
    )

    response = await _request(db, user, f"/api/v1/identity/users/{fresh_identity.id}/risk")
    assert response.status_code == 200
    assert "enabled_stale_identity" not in response.json()["reasons"]
