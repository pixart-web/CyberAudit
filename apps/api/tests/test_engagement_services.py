import pytest

from cyberaudit.engagement_services import (
    EngagementNotFoundError,
    ReportService,
    record_timeline_event,
)
from cyberaudit.models import (
    Criticality,
    Engagement,
    EngagementMode,
    Evidence,
    Finding,
    Organization,
    User,
)


async def _engagement(db, suffix: str) -> tuple[Organization, Engagement, User]:
    organization = Organization(name=f"Tenant {suffix}", slug=f"tenant-{suffix}")
    db.add(organization)
    await db.flush()
    engagement = Engagement(
        organization_id=organization.id,
        client_id="client-" + suffix,
        name=f"Assessment {suffix}",
        code=f"ENG-{suffix}",
        mode=EngagementMode.CLIENT,
    )
    db.add(engagement)
    user = User(
        organization_id=organization.id,
        name="Consultant",
        email=f"consultant-{suffix}@example.invalid",
        password_hash="",  # noqa: S106 - authentication is not exercised here
    )
    db.add(user)
    await db.flush()
    return organization, engagement, user


@pytest.mark.asyncio
async def test_record_timeline_event_rejects_an_unknown_engagement(db):
    organization = Organization(name="Tenant timeline", slug="tenant-timeline")
    db.add(organization)
    await db.flush()
    with pytest.raises(EngagementNotFoundError):
        await record_timeline_event(
            db,
            organization.id,
            "not-a-real-engagement",
            actor_id=None,
            event_type="note",
            summary="anything",
        )


@pytest.mark.asyncio
async def test_record_timeline_event_is_tenant_scoped(db):
    _, engagement_a, user_a = await _engagement(db, "timeline-a")
    organization_b, _, _ = await _engagement(db, "timeline-b")

    entry = await record_timeline_event(
        db,
        user_a.organization_id,
        engagement_a.id,
        actor_id=user_a.id,
        event_type="scope_change",
        summary="Expanded scope to include the staging subnet",
    )
    assert entry.event_type == "scope_change"

    with pytest.raises(EngagementNotFoundError):
        await record_timeline_event(
            db,
            organization_b.id,
            engagement_a.id,
            actor_id=None,
            event_type="scope_change",
            summary="Should not be allowed cross-tenant",
        )


@pytest.mark.asyncio
async def test_report_generation_rejects_unsupported_type(db):
    _, engagement, user = await _engagement(db, "report-type")
    with pytest.raises(ValueError, match="Unsupported report type"):
        await ReportService(db).generate(
            user.organization_id, engagement.id, user, report_type="not-a-real-type"
        )


@pytest.mark.asyncio
async def test_report_generation_assembles_findings_and_evidence_sections(db):
    organization, engagement, user = await _engagement(db, "report-content")
    db.add(
        Finding(
            organization_id=organization.id,
            engagement_id=engagement.id,
            job_id="job-report",
            title="Missing security header",
            description="Observed configuration weakness",
            category="configuration",
            technical_severity=Criticality.LOW,
            confidence="medium",
            affected_component="service-a",
            technical_impact="Limited",
            business_impact="Context dependent",
            remediation_summary="Add the header",
            validation_steps=["Retest"],
            source_adapter="cyberaudit.http_security_headers",
            fingerprint="a" * 64,
        )
    )
    db.add(
        Evidence(
            organization_id=organization.id,
            engagement_id=engagement.id,
            job_id="job-report",
            evidence_type="structured_data",
            title="HTTP response headers",
            content_hash="b" * 64,
            size_bytes=128,
            collected_by_adapter="cyberaudit.http_security_headers",
        )
    )
    await db.flush()

    report = await ReportService(db).generate(organization.id, engagement.id, user)
    assert report.status == "draft"
    assert report.title.startswith("Technical Findings")


@pytest.mark.asyncio
async def test_report_generation_rejects_unknown_engagement(db):
    organization = Organization(name="Tenant report-missing", slug="tenant-report-missing")
    db.add(organization)
    await db.flush()
    user = User(
        organization_id=organization.id,
        name="Consultant",
        email="consultant-report-missing@example.invalid",
        password_hash="",  # noqa: S106 - authentication is not exercised here
    )
    db.add(user)
    await db.flush()
    with pytest.raises(EngagementNotFoundError):
        await ReportService(db).generate(organization.id, "not-a-real-engagement", user)
