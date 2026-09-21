"""Phase 10.4.1 final pass, section 2-8: Incident/Case evidence linking.

`GrcEvidenceLink` is the existing generic evidence-link table (subject_type
+ subject_id) already used for GRC controls. This closes a real
authorization gap found while extending it to Incident/Case: the create
endpoint validated the *evidence*'s tenant ownership but never validated
that the *subject* (control/risk/engagement/finding/asset/incident/case)
both exists and belongs to the caller's tenant -- so a caller could
previously create a link row pointing subject_id at an arbitrary string,
including (if guessed) another tenant's real id. Every case below proves
the fix fails closed.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cyberaudit.db import get_db
from cyberaudit.enterprise_models import CaseRecord, GrcEvidenceLink, Incident
from cyberaudit.main import app
from cyberaudit.models import (
    Engagement,
    EngagementMode,
    Evidence,
    Organization,
    Permission,
    Role,
    User,
)
from cyberaudit.security import current_user

ALL_PERMISSIONS = ["grc_evidence.read", "grc_evidence.manage"]


async def _permission(db: AsyncSession, code: str) -> Permission:
    existing = await db.scalar(select(Permission).where(Permission.code == code))
    if existing:
        return existing
    permission = Permission(code=code, description=code)
    db.add(permission)
    await db.flush()
    return permission


async def _tenant(db: AsyncSession, suffix: str) -> tuple[Organization, User]:
    organization = Organization(name=f"Evidence Tenant {suffix}", slug=f"evidence-tenant-{suffix}")
    db.add(organization)
    await db.flush()
    role = Role(
        name=f"EvidenceOperator-{suffix}",
        permissions=[await _permission(db, code) for code in ALL_PERMISSIONS],
    )
    db.add(role)
    user = User(
        organization_id=organization.id,
        name=f"Evidence Operator {suffix}",
        email=f"evidence-operator-{suffix}@example.invalid",
        password_hash="not-used",  # noqa: S106
        status="active",
    )
    user.roles = [role]
    db.add(user)
    await db.flush()
    return organization, user


async def _engagement(db: AsyncSession, organization_id: str, suffix: str) -> Engagement:
    engagement = Engagement(
        organization_id=organization_id,
        client_id=f"client-{suffix}",
        name=f"Engagement {suffix}",
        code=f"ENG-{suffix}",
        mode=EngagementMode.CLIENT,
    )
    db.add(engagement)
    await db.flush()
    return engagement


async def _evidence(
    db: AsyncSession, organization_id: str, engagement_id: str, suffix: str
) -> Evidence:
    evidence = Evidence(
        organization_id=organization_id,
        engagement_id=engagement_id,
        job_id=f"job-{suffix}",
        evidence_type="document",
        title=f"evidence-{suffix}",
        content_hash="a" * 64,
        collected_by_adapter="cyberaudit.test",
    )
    db.add(evidence)
    await db.flush()
    return evidence


async def _post(db: AsyncSession, user: User, path: str, json: dict) -> httpx.Response:
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
            return await client.post(path, json=json)
    finally:
        app.dependency_overrides.clear()


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
async def test_cannot_link_another_tenants_evidence_to_own_incident(db: AsyncSession):
    org_a, user_a = await _tenant(db, "link-a")
    org_b, _ = await _tenant(db, "link-b")
    incident_a = Incident(organization_id=org_a.id, reference="INC-A", title="own incident")
    db.add(incident_a)
    evidence_b = await _evidence(db, org_b.id, "eng-b-placeholder", "link-b")
    await db.flush()

    response = await _post(
        db,
        user_a,
        "/api/v1/grc/evidence-links",
        {
            "evidence_id": evidence_b.id,
            "subject_type": "incident",
            "subject_id": incident_a.id,
            "purpose": "investigation",
        },
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_cannot_link_own_evidence_to_another_tenants_incident(db: AsyncSession):
    org_a, user_a = await _tenant(db, "subj-a")
    org_b, _ = await _tenant(db, "subj-b")
    engagement_a = await _engagement(db, org_a.id, "subj-a")
    evidence_a = await _evidence(db, org_a.id, engagement_a.id, "subj-a")
    incident_b = Incident(organization_id=org_b.id, reference="INC-B", title="tenant b incident")
    db.add(incident_b)
    await db.flush()

    response = await _post(
        db,
        user_a,
        "/api/v1/grc/evidence-links",
        {
            "evidence_id": evidence_a.id,
            "subject_type": "incident",
            "subject_id": incident_b.id,
            "purpose": "investigation",
        },
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_cannot_link_evidence_to_a_nonexistent_case(db: AsyncSession):
    """Invalid object relationships fail closed, per section 7 -- a

    subject_id that simply doesn't exist must 404, not silently succeed.
    """
    org_a, user_a = await _tenant(db, "nx-a")
    engagement_a = await _engagement(db, org_a.id, "nx-a")
    evidence_a = await _evidence(db, org_a.id, engagement_a.id, "nx-a")

    response = await _post(
        db,
        user_a,
        "/api/v1/grc/evidence-links",
        {
            "evidence_id": evidence_a.id,
            "subject_type": "case",
            "subject_id": "00000000-0000-0000-0000-000000000000",
            "purpose": "investigation",
        },
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_case_evidence_link_succeeds_for_the_callers_own_case(db: AsyncSession):
    org_a, user_a = await _tenant(db, "case-ok")
    engagement_a = await _engagement(db, org_a.id, "case-ok")
    evidence_a = await _evidence(db, org_a.id, engagement_a.id, "case-ok")
    incident_a = Incident(organization_id=org_a.id, reference="INC-CASE-OK", title="t")
    db.add(incident_a)
    await db.flush()
    case_a = CaseRecord(
        organization_id=org_a.id, incident_id=incident_a.id, reference="CASE-OK", title="t"
    )
    db.add(case_a)
    await db.flush()

    response = await _post(
        db,
        user_a,
        "/api/v1/grc/evidence-links",
        {
            "evidence_id": evidence_a.id,
            "subject_type": "case",
            "subject_id": case_a.id,
            "purpose": "chain of custody",
        },
    )
    assert response.status_code == 201
    body = response.json()
    assert body["subject_type"] == "case"
    assert body["subject_id"] == case_a.id

    listed = await db.scalar(select(GrcEvidenceLink).where(GrcEvidenceLink.subject_id == case_a.id))
    assert listed is not None
    assert listed.organization_id == org_a.id


@pytest.mark.asyncio
async def test_evidence_links_list_embeds_the_real_evidence_record_scoped_to_the_tenant(
    db: AsyncSession,
):
    """The list endpoint embeds the actual Evidence row per link (avoiding

    a frontend N+1), but the embed itself must stay tenant-scoped -- a
    link somehow pointing at another tenant's evidence_id must embed
    nothing rather than leak that row.
    """
    org_a, user_a = await _tenant(db, "embed-a")
    org_b, _ = await _tenant(db, "embed-b")
    engagement_a = await _engagement(db, org_a.id, "embed-a")
    evidence_a = await _evidence(db, org_a.id, engagement_a.id, "embed-a")
    incident_a = Incident(organization_id=org_a.id, reference="INC-EMBED", title="t")
    db.add(incident_a)
    await db.flush()
    db.add(
        GrcEvidenceLink(
            organization_id=org_a.id,
            evidence_id=evidence_a.id,
            subject_type="incident",
            subject_id=incident_a.id,
            purpose="chain of custody",
        )
    )
    # A link row that (however it got there) points at another tenant's
    # evidence -- the embed for this row must come back None, not leak it.
    evidence_b = await _evidence(db, org_b.id, "eng-b-placeholder", "embed-b")
    db.add(
        GrcEvidenceLink(
            organization_id=org_a.id,
            evidence_id=evidence_b.id,
            subject_type="incident",
            subject_id=incident_a.id,
            purpose="dangling reference",
        )
    )
    await db.flush()

    response = await _get(
        db, user_a, f"/api/v1/grc/evidence-links?subject_type=incident&subject_id={incident_a.id}"
    )
    assert response.status_code == 200
    items = {item["evidence_id"]: item["evidence"] for item in response.json()["items"]}
    assert items[evidence_a.id]["title"] == "evidence-embed-a"
    assert items[evidence_b.id] is None
