"""Engagement notes/timeline and report generation (10.3.6 / section 38).

Report generation assembles sections from data CyberAudit already recorded
for one engagement -- findings and evidence -- plus, optionally, one
AI-generated executive summary produced by the ``report_agent``
(:mod:`cyberaudit.agent_runtime`). Every section's ``content_type`` records
whether it is observed evidence, a deterministic finding, or an
AI-generated explanation; an AI-generated section always carries the
citations that grounded it, and is never silently promoted to "evidence" or
"finding".
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cyberaudit.agent_runtime import CyberAgentRuntime
from cyberaudit.engagement_models import EngagementTimelineEntry, Report, ReportSection
from cyberaudit.models import Engagement, Evidence, Finding, User
from cyberaudit.redaction import redact_text

REPORT_TYPES = frozenset(
    {
        "technical_findings",
        "executive_summary",
        "risk_summary",
        "compliance_assessment",
    }
)


class EngagementNotFoundError(LookupError):
    pass


async def _get_engagement(db: AsyncSession, organization_id: str, engagement_id: str) -> Engagement:
    engagement = await db.get(Engagement, engagement_id)
    if not engagement or engagement.organization_id != organization_id:
        raise EngagementNotFoundError("Engagement not found")
    return engagement


async def record_timeline_event(
    db: AsyncSession,
    organization_id: str,
    engagement_id: str,
    *,
    actor_id: str | None,
    event_type: str,
    summary: str,
    metadata: dict[str, object] | None = None,
) -> EngagementTimelineEntry:
    await _get_engagement(db, organization_id, engagement_id)
    entry = EngagementTimelineEntry(
        organization_id=organization_id,
        engagement_id=engagement_id,
        actor_id=actor_id,
        event_type=event_type,
        summary=redact_text(summary, 500),
        event_metadata=metadata or {},
    )
    db.add(entry)
    await db.flush()
    return entry


class ReportService:
    """Assembles a Report from already-recorded engagement data."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def generate(
        self,
        organization_id: str,
        engagement_id: str,
        user: User,
        *,
        report_type: str = "technical_findings",
        include_ai_summary: bool = False,
    ) -> Report:
        if report_type not in REPORT_TYPES:
            raise ValueError(f"Unsupported report type: {report_type}")
        engagement = await _get_engagement(self.db, organization_id, engagement_id)

        report = Report(
            organization_id=organization_id,
            engagement_id=engagement_id,
            report_type=report_type,
            title=f"{report_type.replace('_', ' ').title()} — {engagement.name}",
            generated_by=user.id,
        )
        self.db.add(report)
        await self.db.flush()

        position = 0
        findings = list(
            (
                await self.db.scalars(
                    select(Finding).where(
                        Finding.organization_id == organization_id,
                        Finding.engagement_id == engagement_id,
                    )
                )
            ).all()
        )
        for finding in findings:
            self.db.add(
                ReportSection(
                    report_id=report.id,
                    position=position,
                    heading=redact_text(finding.title, 300),
                    content_type="finding",
                    body=redact_text(finding.description, 4000),
                    source_references=[finding.id],
                )
            )
            position += 1

        evidence_rows = list(
            (
                await self.db.scalars(
                    select(Evidence).where(
                        Evidence.organization_id == organization_id,
                        Evidence.engagement_id == engagement_id,
                    )
                )
            ).all()
        )
        for evidence in evidence_rows:
            self.db.add(
                ReportSection(
                    report_id=report.id,
                    position=position,
                    heading=redact_text(evidence.title, 300),
                    content_type="evidence",
                    body=(
                        f"{evidence.evidence_type}: {redact_text(evidence.description, 2000)}"
                        if evidence.description
                        else evidence.evidence_type
                    ),
                    source_references=[evidence.id],
                )
            )
            position += 1

        if include_ai_summary:
            answer = await CyberAgentRuntime(self.db).ask(
                "report_agent",
                user,
                f"Draft an executive summary for engagement {engagement.name}",
            )
            self.db.add(
                ReportSection(
                    report_id=report.id,
                    position=position,
                    heading="Executive summary (AI-generated, requires review)",
                    content_type="ai_generated",
                    body=answer.response,
                    source_references=[],
                    ai_citations=answer.citations,
                )
            )
            position += 1

        await self.db.flush()
        return report
