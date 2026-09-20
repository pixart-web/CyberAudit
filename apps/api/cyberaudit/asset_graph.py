"""PostgreSQL-backed Cyber Asset Graph and explainable path analysis."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Any, Protocol

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from cyberaudit.models import Asset, Finding
from cyberaudit.phase4_models import AssetRelationship, AttackPath, AttackPathStep, utcnow

ALLOWED_RELATIONSHIPS = {
    "belongs_to",
    "located_in",
    "resolves_to",
    "exposes",
    "hosts",
    "runs",
    "depends_on",
    "communicates_with",
    "protected_by",
    "authenticated_by",
    "managed_by",
    "part_of",
    "connected_to",
    "contains",
    "serves",
    "uses_certificate",
    "affected_by",
    "evidenced_by",
    "mitigated_by",
    "discovered_from",
    "observed_on",
    "associated_with",
    "reachable_from",
    "accessible_via",
    "supports_business_service",
}


class AssetGraphRepository(Protocol):
    async def neighborhood(
        self, organization_id: str, asset_id: str | None, limit: int
    ) -> tuple[list[Asset], list[AssetRelationship]]: ...


class PostgreSQLAssetGraphRepository:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def neighborhood(
        self, organization_id: str, asset_id: str | None, limit: int = 200
    ) -> tuple[list[Asset], list[AssetRelationship]]:
        limit = max(1, min(limit, 500))
        relationship_query = select(AssetRelationship).where(
            AssetRelationship.organization_id == organization_id,
            AssetRelationship.active.is_(True),
        )
        if asset_id:
            relationship_query = relationship_query.where(
                or_(
                    AssetRelationship.source_asset_id == asset_id,
                    AssetRelationship.target_asset_id == asset_id,
                )
            )
        relationships = list((await self.db.scalars(relationship_query.limit(limit))).all())
        asset_ids = {
            value
            for relationship in relationships
            for value in (relationship.source_asset_id, relationship.target_asset_id)
        }
        if asset_id:
            asset_ids.add(asset_id)
        asset_query = select(Asset).where(
            Asset.organization_id == organization_id,
            Asset.deleted_at.is_(None),
        )
        if asset_ids:
            asset_query = asset_query.where(Asset.id.in_(asset_ids))
        assets = list((await self.db.scalars(asset_query.limit(limit))).all())
        return assets, relationships


class CyberAssetGraphService:
    def __init__(self, repository: AssetGraphRepository):
        self.repository = repository

    async def graph(
        self, organization_id: str, asset_id: str | None = None, limit: int = 200
    ) -> dict[str, Any]:
        assets, relationships = await self.repository.neighborhood(organization_id, asset_id, limit)
        return {
            "nodes": [
                {
                    "id": asset.id,
                    "label": asset.name,
                    "type": asset.asset_type,
                    "criticality": asset.business_criticality,
                    "exposure": "internet" if asset.internet_exposed else "internal",
                    "risk_score": asset.risk_score,
                    "confidence": asset.confidence,
                }
                for asset in assets
            ],
            "edges": [
                {
                    "id": relation.id,
                    "source": relation.source_asset_id,
                    "target": relation.target_asset_id,
                    "type": relation.relationship_type,
                    "confidence": relation.confidence,
                    "reviewed": relation.reviewed,
                }
                for relation in relationships
            ],
            "limit": max(1, min(limit, 500)),
            "progressive": True,
        }


@dataclass(frozen=True)
class CandidateStep:
    relationship: AssetRelationship
    source: str
    target: str


class AttackPathAnalysisService:
    version = "attack-path-1.0.0"

    def __init__(self, db: AsyncSession):
        self.db = db

    async def analyze(
        self,
        organization_id: str,
        engagement_id: str | None = None,
        max_depth: int = 5,
        maximum_paths: int = 20,
    ) -> list[AttackPath]:
        max_depth = max(1, min(max_depth, 8))
        maximum_paths = max(1, min(maximum_paths, 50))
        assets = list(
            (
                await self.db.scalars(
                    select(Asset).where(
                        Asset.organization_id == organization_id,
                        Asset.deleted_at.is_(None),
                    )
                )
            ).all()
        )
        relationships = list(
            (
                await self.db.scalars(
                    select(AssetRelationship).where(
                        AssetRelationship.organization_id == organization_id,
                        AssetRelationship.active.is_(True),
                        AssetRelationship.confidence >= 0.5,
                    )
                )
            ).all()
        )
        by_id = {asset.id: asset for asset in assets}
        entries = [asset for asset in assets if asset.internet_exposed]
        targets = {
            asset.id
            for asset in assets
            if asset.business_criticality in {"high", "critical"} and not asset.internet_exposed
        }
        adjacency: dict[str, list[CandidateStep]] = {}
        for relation in relationships:
            adjacency.setdefault(relation.source_asset_id, []).append(
                CandidateStep(relation, relation.source_asset_id, relation.target_asset_id)
            )
            if relation.direction == "bidirectional":
                adjacency.setdefault(relation.target_asset_id, []).append(
                    CandidateStep(relation, relation.target_asset_id, relation.source_asset_id)
                )
        created: list[AttackPath] = []
        for entry in entries:
            queue: deque[tuple[str, list[CandidateStep], frozenset[str]]] = deque(
                [(entry.id, [], frozenset({entry.id}))]
            )
            while queue and len(created) < maximum_paths:
                node, steps, visited = queue.popleft()
                if node in targets and steps:
                    path = await self._persist_candidate(
                        organization_id, engagement_id, entry, by_id[node], steps
                    )
                    created.append(path)
                    continue
                if len(steps) >= max_depth:
                    continue
                for step in adjacency.get(node, []):
                    if step.target in visited:
                        continue
                    queue.append((step.target, [*steps, step], visited | {step.target}))
        await self.db.flush()
        return created

    async def _persist_candidate(
        self,
        organization_id: str,
        engagement_id: str | None,
        entry: Asset,
        target: Asset,
        steps: list[CandidateStep],
    ) -> AttackPath:
        confidence = min(step.relationship.confidence for step in steps)
        findings = list(
            (
                await self.db.scalars(
                    select(Finding).where(
                        Finding.organization_id == organization_id,
                        Finding.asset_id.in_([step.target for step in steps]),
                        Finding.status == "open",
                    )
                )
            ).all()
        )
        severity_weight = {"low": 20, "medium": 45, "high": 70, "critical": 95}
        finding_risk = max(
            [severity_weight.get(str(finding.technical_severity), 30) for finding in findings],
            default=30,
        )
        overall = round(min(100.0, finding_risk * confidence + target.risk_score * 0.25), 2)
        severity = "critical" if overall >= 80 else "high" if overall >= 60 else "medium"
        path = AttackPath(
            organization_id=organization_id,
            engagement_id=engagement_id,
            name=f"{entry.name} → {target.name}",
            description=(
                "Caminho candidato inferido de relações observadas; não representa exploração "
                "nem confirma que o percurso seja executável."
            ),
            entry_asset_id=entry.id,
            target_asset_id=target.id,
            path_type="exposure_to_critical_asset",
            severity=severity,
            confidence=confidence,
            likelihood=round(confidence * 100, 2),
            impact=max(target.risk_score, 50),
            overall_risk=overall,
            status="candidate",
            generated_by="deterministic_graph_rules",
            calculation_version=self.version,
        )
        self.db.add(path)
        await self.db.flush()
        finding_by_asset = {finding.asset_id: finding for finding in findings}
        for sequence, item in enumerate(steps, start=1):
            finding = finding_by_asset.get(item.target)
            self.db.add(
                AttackPathStep(
                    attack_path_id=path.id,
                    sequence=sequence,
                    source_asset_id=item.source,
                    target_asset_id=item.target,
                    relationship_id=item.relationship.id,
                    finding_id=finding.id if finding else None,
                    condition="Relação observada e ativa",
                    explanation=(
                        f"Facto: relação {item.relationship.relationship_type}. "
                        "Inferência: poderá permitir dependência ou alcance lógico."
                    ),
                    confidence=item.relationship.confidence,
                    evidence=(
                        [item.relationship.evidence_id] if item.relationship.evidence_id else []
                    ),
                    mitigation="Rever segmentação, exposição e controlos do ativo relacionado.",
                    created_at=utcnow(),
                )
            )
        return path
