import hashlib

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cyberaudit.models import Finding


class FindingCorrelationService:
    """Correlates observations without widening scope or raising severity."""

    async def correlate_engagement(
        self,
        db: AsyncSession,
        *,
        organization_id: str,
        engagement_id: str,
    ) -> dict[str, int]:
        findings = list(
            (
                await db.scalars(
                    select(Finding).where(
                        Finding.organization_id == organization_id,
                        Finding.engagement_id == engagement_id,
                    )
                )
            ).all()
        )
        groups: dict[str, list[Finding]] = {}
        for finding in findings:
            key = self.correlation_key(finding)
            groups.setdefault(key, []).append(finding)
        correlated = 0
        confidence_raised = 0
        for related in groups.values():
            adapters = {item.source_adapter for item in related}
            if len(adapters) < 2:
                continue
            correlated += len(related)
            for finding in related:
                existing = {item.get("name") for item in finding.standards}
                marker = {"name": "CyberAudit", "reference": "multi-source-correlation"}
                if marker["name"] not in existing:
                    finding.standards = [*finding.standards, marker]
                if finding.confidence == "medium":
                    finding.confidence = "high"
                    confidence_raised += 1
        return {"correlated": correlated, "confidence_raised": confidence_raised}

    @staticmethod
    def correlation_key(finding: Finding) -> str:
        parts = [
            finding.organization_id,
            finding.engagement_id,
            finding.asset_id or "",
            finding.category,
            finding.affected_component.lower(),
            finding.location or "",
            finding.observed_value or "",
        ]
        return hashlib.sha256("\x1f".join(parts).encode()).hexdigest()
