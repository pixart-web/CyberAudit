"""Professional PDF export: real data only, tenant-isolated, audited."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import datetime, timezone

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cyberaudit.admin_api import ensure_rbac
from cyberaudit.db import get_db
from cyberaudit.engagement_models import Report, ReportSection
from cyberaudit.main import app
from cyberaudit.models import (
    AuditLog,
    Client,
    Criticality,
    Engagement,
    EngagementMode,
    Finding,
    Organization,
    Role,
    User,
)
from cyberaudit.report_pdf import ReportData, ReportFinding, render_report_pdf
from cyberaudit.security import current_user


def test_renderer_includes_only_recorded_data_and_flags_unverified():
    data = ReportData(
        title="Executive Summary — Northstar",
        report_type="executive_summary",
        status="draft",
        organization="Pixart",
        client="Northstar Industries",
        engagement_name="Enterprise Assessment",
        engagement_code="NORTH-1",
        engagement_mode="client",
        period="2026-10-01 → 2026-11-01",
        generated_by="Tiago",
        generated_at=datetime(2026, 10, 8, tzinfo=timezone.utc),
        scope_targets=["cidr: 10.20.0.0/24"],
        findings=[
            ReportFinding(
                "Exposed admin interface",
                "high",
                "open",
                "unverified",
                "core-fw-01",
                "Reachable from user VLAN",
                "Restrict access",
                imported=True,
            )
        ],
        ai_sections=[("Resumo", "Texto gerado")],
    )
    pdf = render_report_pdf(data, compress=False)
    assert pdf.startswith(b"%PDF")
    for needle in (
        b"Northstar Industries",
        b"Exposed admin interface",
        b"10.20.0.0/24",
        b"requer revis",
    ):
        assert needle in pdf.replace(b"\\(", b"(")
    assert b"unverified" in pdf


async def _tenant(db: AsyncSession, slug: str):
    org = Organization(name=f"Org {slug}", slug=slug)
    db.add(org)
    await db.flush()
    role = await db.scalar(select(Role).where(Role.name == "Administrator"))
    user = User(
        organization_id=org.id,
        name=f"U {slug}",
        email=f"u@{slug}.example.com",
        password_hash="not-a-real-hash",  # noqa: S106
        roles=[role],
    )
    client = Client(organization_id=org.id, name=f"Client {slug}")
    db.add_all([user, client])
    await db.flush()
    eng = Engagement(
        organization_id=org.id,
        client_id=client.id,
        name="E",
        code=f"E-{slug}",
        mode=EngagementMode.CLIENT,
        owner_id=user.id,
    )
    db.add(eng)
    await db.flush()
    db.add(
        Finding(
            organization_id=org.id,
            engagement_id=eng.id,
            job_id="j",
            title="Secret finding " + slug,
            description="d",
            category="c",
            technical_severity=Criticality.HIGH,
            confidence="high",
            affected_component="x",
            technical_impact="t",
            business_impact="b",
            remediation_summary="fix",
            validation_steps=[],
            source_adapter="manual",
            fingerprint=f"fp-{slug}",
        )
    )
    report = Report(
        organization_id=org.id, engagement_id=eng.id, title=f"Report {slug}", generated_by=user.id
    )
    db.add(report)
    await db.flush()
    db.add(
        ReportSection(
            report_id=report.id, position=0, heading="h", content_type="finding", body="b"
        )
    )
    await db.commit()
    return user, report


@pytest.mark.asyncio
async def test_export_endpoint_is_tenant_isolated_and_audited(db: AsyncSession):
    await ensure_rbac(db)
    await db.commit()
    user_a, report_a = await _tenant(db, "a")
    _, report_b = await _tenant(db, "b")

    async def override_db() -> AsyncIterator[AsyncSession]:
        yield db

    async def override_user() -> User:
        return await db.get(User, user_a.id, populate_existing=True)  # type: ignore[return-value]

    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[current_user] = override_user
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
            base_url="http://testserver",
        ) as c:
            ok = await c.get(f"/api/v1/reports/{report_a.id}/export.pdf")
            foreign = await c.get(f"/api/v1/reports/{report_b.id}/export.pdf")
    finally:
        app.dependency_overrides.clear()
    assert ok.status_code == 200, ok.text
    assert ok.headers["content-type"] == "application/pdf" and ok.content.startswith(b"%PDF")
    assert ok.headers["cache-control"] == "no-store"
    assert foreign.status_code == 404
    assert "report.exported" in {a for (a,) in (await db.execute(select(AuditLog.action))).all()}
