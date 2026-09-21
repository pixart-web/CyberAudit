"""Phase 10.4.1: cross-tenant isolation for the new Workspace-detail filters.

`?finding_id=`, `?incident_id=`, `?control_id=`, `?subject_type=&subject_id=`
and `GET /grc/controls/{id}` were all added in this phase so a Workspace
detail page could scope a related collection to one entity. Each of them is
layered on top of an existing tenant-scoped `page()`/`_page()` query, but a
new filter parameter is exactly the kind of change that can silently widen
what a caller sees -- so this proves a caller who knows another tenant's
identifier still gets nothing back, never that tenant's row.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import datetime, timezone

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cyberaudit.db import get_db
from cyberaudit.enterprise_models import (
    CaseRecord,
    ControlAssessment,
    DetectionAlert,
    DetectionRule,
    FrameworkControlMapping,
    GrcEvidenceLink,
    Incident,
    SecurityEvent,
    UnifiedControl,
)
from cyberaudit.main import app
from cyberaudit.models import (
    Criticality,
    Evidence,
    Finding,
    Organization,
    Permission,
    Retest,
    Role,
    User,
)
from cyberaudit.security import current_user

ALL_PERMISSIONS = [
    "findings.read",
    "retests.read",
    "detections.read",
    "cases.read",
    "controls.read",
    "grc_evidence.read",
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
    organization = Organization(name=f"Filter Tenant {suffix}", slug=f"filter-tenant-{suffix}")
    db.add(organization)
    await db.flush()
    role = Role(
        name=f"Operator-{suffix}",
        permissions=[await _permission(db, code) for code in ALL_PERMISSIONS],
    )
    db.add(role)
    user = User(
        organization_id=organization.id,
        name=f"Operator {suffix}",
        email=f"operator-{suffix}@example.invalid",
        password_hash="not-used",  # noqa: S106
        status="active",
    )
    user.roles = [role]
    db.add(user)
    await db.flush()
    return organization, user


async def _get(db: AsyncSession, user: User, path: str) -> httpx.Response:
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
async def test_retests_finding_id_filter_is_tenant_scoped(db: AsyncSession):
    org_a, user_a = await _tenant(db, "retest-a")
    org_b, _ = await _tenant(db, "retest-b")
    finding_b = Finding(
        organization_id=org_b.id,
        engagement_id="eng-b",
        job_id="job-b",
        title="Tenant B finding",
        description="Observed",
        category="configuration",
        technical_severity=Criticality.HIGH,
        confidence="medium",
        affected_component="service-b",
        technical_impact="Limited",
        business_impact="Context dependent",
        remediation_summary="Review",
        source_adapter="cyberaudit.test",
        fingerprint="b" * 64,
    )
    db.add(finding_b)
    await db.flush()
    retest_b = Retest(
        organization_id=org_b.id,
        engagement_id="eng-b",
        finding_id=finding_b.id,
        original_job_id="job-b",
        requested_by="user-b",
    )
    db.add(retest_b)
    await db.flush()

    response = await _get(db, user_a, f"/api/v1/retests?finding_id={finding_b.id}")
    assert response.status_code == 200
    assert response.json()["items"] == []


@pytest.mark.asyncio
async def test_cases_and_alerts_incident_id_filter_is_tenant_scoped(db: AsyncSession):
    org_a, user_a = await _tenant(db, "incident-a")
    org_b, _ = await _tenant(db, "incident-b")
    incident_b = Incident(organization_id=org_b.id, reference="INC-B-1", title="Tenant B incident")
    db.add(incident_b)
    event_b = SecurityEvent(
        organization_id=org_b.id,
        source="test",
        external_id="ext-b-1",
        event_type="test",
        occurred_at=datetime.now(timezone.utc),
        summary="test event",
        content_hash="e" * 64,
    )
    rule_b = DetectionRule(
        organization_id=org_b.id,
        code="RULE-B-1",
        name="rule-b",
        owner_id="user-b",
    )
    db.add_all([event_b, rule_b])
    await db.flush()
    case_b = CaseRecord(
        organization_id=org_b.id, incident_id=incident_b.id, reference="CASE-B-1", title="t"
    )
    alert_b = DetectionAlert(
        organization_id=org_b.id,
        rule_id=rule_b.id,
        event_id=event_b.id,
        incident_id=incident_b.id,
        title="alert-b",
        severity="high",
        fingerprint="fp-b-1",
    )
    db.add_all([case_b, alert_b])
    await db.flush()

    cases_response = await _get(db, user_a, f"/api/v1/cases?incident_id={incident_b.id}")
    alerts_response = await _get(
        db, user_a, f"/api/v1/detections/alerts?incident_id={incident_b.id}"
    )
    assert cases_response.status_code == 200
    assert cases_response.json()["items"] == []
    assert alerts_response.status_code == 200
    assert alerts_response.json()["items"] == []


@pytest.mark.asyncio
async def test_control_mappings_assessments_and_evidence_filters_are_tenant_scoped(
    db: AsyncSession,
):
    org_a, user_a = await _tenant(db, "control-a")
    org_b, _ = await _tenant(db, "control-b")
    control_b = UnifiedControl(
        organization_id=org_b.id,
        code="CTL-B-1",
        title="Tenant B control",
        description="Test control",
        domain="access",
    )
    db.add(control_b)
    await db.flush()
    mapping_b = FrameworkControlMapping(
        organization_id=org_b.id,
        control_id=control_b.id,
        framework_id="framework-b",
        external_control_id="A.1",
        external_title="External A.1",
    )
    assessment_b = ControlAssessment(
        organization_id=org_b.id,
        control_id=control_b.id,
        assessor_id="user-b",
    )
    evidence_b = Evidence(
        organization_id=org_b.id,
        engagement_id="eng-b",
        job_id="job-b",
        evidence_type="document",
        title="evidence-b",
        content_hash="c" * 64,
        collected_by_adapter="cyberaudit.test",
    )
    db.add_all([mapping_b, assessment_b, evidence_b])
    await db.flush()
    grc_link_b = GrcEvidenceLink(
        organization_id=org_b.id,
        evidence_id=evidence_b.id,
        subject_type="control",
        subject_id=control_b.id,
        purpose="test",
    )
    db.add(grc_link_b)
    await db.flush()

    control_get = await _get(db, user_a, f"/api/v1/grc/controls/{control_b.id}")
    mappings = await _get(db, user_a, f"/api/v1/grc/control-mappings?control_id={control_b.id}")
    assessments = await _get(
        db, user_a, f"/api/v1/grc/control-assessments?control_id={control_b.id}"
    )
    evidence_links = await _get(
        db,
        user_a,
        f"/api/v1/grc/evidence-links?subject_type=control&subject_id={control_b.id}",
    )

    assert control_get.status_code == 404
    assert mappings.status_code == 200 and mappings.json()["items"] == []
    assert assessments.status_code == 200 and assessments.json()["items"] == []
    assert evidence_links.status_code == 200 and evidence_links.json()["items"] == []
