"""Phase 10.4.1 SOC Workspace: cross-tenant isolation for the new single-item

GET endpoints (security event, detection alert, case, hunt) and the new
``?event_id=`` alert filter, plus a correctness check for hunt execution
(declarative, bounded, no eval/free-form SQL -- invariant 22).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cyberaudit.db import get_db
from cyberaudit.enterprise_models import (
    CaseRecord,
    DetectionAlert,
    DetectionRule,
    Incident,
    SecurityEvent,
    ThreatHunt,
)
from cyberaudit.main import app
from cyberaudit.models import Organization, Permission, Role, User
from cyberaudit.security import current_user

ALL_PERMISSIONS = [
    "events.read",
    "detections.read",
    "cases.read",
    "cases.manage",
    "hunts.read",
    "hunts.manage",
]


async def _permission(db: AsyncSession, code: str) -> Permission:
    existing = await db.scalar(select(Permission).where(Permission.code == code))
    if existing:
        return existing
    permission = Permission(code=code, description=code)
    db.add(permission)
    await db.flush()
    return permission


async def _tenant(db: AsyncSession, suffix: str) -> tuple[Organization, User]:
    organization = Organization(name=f"SOC Tenant {suffix}", slug=f"soc-tenant-{suffix}")
    db.add(organization)
    await db.flush()
    role = Role(
        name=f"SocOperator-{suffix}",
        permissions=[await _permission(db, code) for code in ALL_PERMISSIONS],
    )
    db.add(role)
    user = User(
        organization_id=organization.id,
        name=f"SOC Operator {suffix}",
        email=f"soc-operator-{suffix}@example.invalid",
        password_hash="not-used",  # noqa: S106
        status="active",
    )
    user.roles = [role]
    db.add(user)
    await db.flush()
    return organization, user


async def _request(
    db: AsyncSession, user: User, method: str, path: str, json: dict | None = None
) -> httpx.Response:
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
            return await client.request(method, path, json=json)
    finally:
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_security_event_detail_is_tenant_scoped(db: AsyncSession):
    org_a, user_a = await _tenant(db, "event-a")
    org_b, _ = await _tenant(db, "event-b")
    event_b = SecurityEvent(
        organization_id=org_b.id,
        source="test",
        external_id="ext-b-1",
        event_type="test",
        occurred_at=datetime.now(timezone.utc),
        summary="tenant b event",
        content_hash="e" * 64,
    )
    db.add(event_b)
    await db.flush()

    response = await _request(db, user_a, "GET", f"/api/v1/security-events/{event_b.id}")
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_alert_detail_and_event_id_filter_are_tenant_scoped(db: AsyncSession):
    org_a, user_a = await _tenant(db, "alert-a")
    org_b, _ = await _tenant(db, "alert-b")
    event_b = SecurityEvent(
        organization_id=org_b.id,
        source="test",
        external_id="ext-b-2",
        event_type="test",
        occurred_at=datetime.now(timezone.utc),
        summary="tenant b event",
        content_hash="f" * 64,
    )
    rule_b = DetectionRule(
        organization_id=org_b.id, code="RULE-B", name="rule-b", owner_id="user-b"
    )
    db.add_all([event_b, rule_b])
    await db.flush()
    alert_b = DetectionAlert(
        organization_id=org_b.id,
        rule_id=rule_b.id,
        event_id=event_b.id,
        title="alert-b",
        severity="high",
        fingerprint="fp-alert-b",
    )
    db.add(alert_b)
    await db.flush()

    detail = await _request(db, user_a, "GET", f"/api/v1/detections/alerts/{alert_b.id}")
    assert detail.status_code == 404

    listed = await _request(db, user_a, "GET", f"/api/v1/detections/alerts?event_id={event_b.id}")
    assert listed.status_code == 200
    assert listed.json()["items"] == []


@pytest.mark.asyncio
async def test_case_detail_is_tenant_scoped(db: AsyncSession):
    org_a, user_a = await _tenant(db, "case-a")
    org_b, _ = await _tenant(db, "case-b")
    incident_b = Incident(organization_id=org_b.id, reference="INC-B", title="tenant b incident")
    db.add(incident_b)
    await db.flush()
    case_b = CaseRecord(
        organization_id=org_b.id,
        incident_id=incident_b.id,
        reference="CASE-B",
        title="tenant b case",
    )
    db.add(case_b)
    await db.flush()

    response = await _request(db, user_a, "GET", f"/api/v1/cases/{case_b.id}")
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_case_creation_cannot_target_another_tenants_incident(db: AsyncSession):
    org_a, user_a = await _tenant(db, "case-create-a")
    org_b, _ = await _tenant(db, "case-create-b")
    incident_b = Incident(organization_id=org_b.id, reference="INC-B", title="tenant b incident")
    db.add(incident_b)
    await db.flush()

    response = await _request(
        db,
        user_a,
        "POST",
        "/api/v1/cases",
        json={"incident_id": incident_b.id, "title": "Attempted cross-tenant case"},
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_case_creation_succeeds_for_the_callers_own_incident(db: AsyncSession):
    organization, user = await _tenant(db, "case-create-own")
    incident = Incident(organization_id=organization.id, reference="INC-OWN", title="Own incident")
    db.add(incident)
    await db.flush()

    response = await _request(
        db,
        user,
        "POST",
        "/api/v1/cases",
        json={"incident_id": incident.id, "title": "Investigate anomalous auth activity"},
    )
    assert response.status_code == 201
    body = response.json()
    assert body["incident_id"] == incident.id
    assert body["reference"].startswith("CASE-")


@pytest.mark.asyncio
async def test_hunt_detail_and_execute_are_tenant_scoped(db: AsyncSession):
    org_a, user_a = await _tenant(db, "hunt-a")
    org_b, _ = await _tenant(db, "hunt-b")
    hunt_b = ThreatHunt(
        organization_id=org_b.id,
        name="hunt-b",
        hypothesis="test",
        query={"event_type": "login_failed"},
        owner_id="user-b",
        time_from=datetime.now(timezone.utc) - timedelta(days=1),
        time_until=datetime.now(timezone.utc),
    )
    db.add(hunt_b)
    await db.flush()

    detail = await _request(db, user_a, "GET", f"/api/v1/hunts/{hunt_b.id}")
    assert detail.status_code == 404

    execute = await _request(db, user_a, "POST", f"/api/v1/hunts/{hunt_b.id}/execute")
    assert execute.status_code == 404


@pytest.mark.asyncio
async def test_hunt_execution_only_matches_allowlisted_fields_within_time_window(db: AsyncSession):
    """Invariant 22: a hunt's query is a bounded equality filter over an

    explicit field allowlist -- never eval, never free-form SQL. This
    proves it matches the right events and stays within the hunt's own
    organization and time window.
    """
    organization, user = await _tenant(db, "hunt-exec")
    now = datetime.now(timezone.utc)
    matching_event = SecurityEvent(
        organization_id=organization.id,
        source="test",
        external_id="ext-match",
        event_type="login_failed",
        occurred_at=now - timedelta(hours=1),
        summary="matching event",
        content_hash="a" * 64,
    )
    non_matching_event = SecurityEvent(
        organization_id=organization.id,
        source="test",
        external_id="ext-no-match",
        event_type="login_success",
        occurred_at=now - timedelta(hours=1),
        summary="non-matching event",
        content_hash="b" * 64,
    )
    outside_window_event = SecurityEvent(
        organization_id=organization.id,
        source="test",
        external_id="ext-outside",
        event_type="login_failed",
        occurred_at=now - timedelta(days=10),
        summary="outside time window",
        content_hash="c" * 64,
    )
    db.add_all([matching_event, non_matching_event, outside_window_event])
    await db.flush()
    hunt = ThreatHunt(
        organization_id=organization.id,
        name="brute-force-hunt",
        hypothesis="Repeated login failures may indicate brute force",
        query={"event_type": "login_failed"},
        owner_id=user.id,
        time_from=now - timedelta(days=1),
        time_until=now,
    )
    db.add(hunt)
    await db.flush()

    response = await _request(db, user, "POST", f"/api/v1/hunts/{hunt.id}/execute")
    assert response.status_code == 200
    body = response.json()
    assert body["result_count"] == 1
    assert body["findings"][0]["event_id"] == matching_event.id
    assert body["status"] == "completed"
