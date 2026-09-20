"""Auditable maintenance entry points for CyberAudit OS Phase 4."""

from __future__ import annotations

import argparse
import asyncio

from sqlalchemy import select

from cyberaudit.asset_graph import AttackPathAnalysisService
from cyberaudit.db import SessionLocal
from cyberaudit.models import Asset, Organization
from cyberaudit.phase4_models import VulnerabilityFeed
from cyberaudit.phase4_worker import sync_vulnerability_feed
from cyberaudit.risk_engine import ContextualRiskEngine, RiskContext


async def sync_feeds() -> None:
    async with SessionLocal() as db:
        feeds = list(
            (
                await db.scalars(
                    select(VulnerabilityFeed).where(VulnerabilityFeed.enabled.is_(True))
                )
            ).all()
        )
        for feed in feeds:
            sync_vulnerability_feed.send(feed.id)
        print(f"Queued {len(feeds)} allowlisted vulnerability feed sync(s).")


async def recalculate_risk() -> None:
    engine = ContextualRiskEngine()
    async with SessionLocal() as db:
        assets = list((await db.scalars(select(Asset).where(Asset.deleted_at.is_(None)))).all())
        for asset in assets:
            result = engine.calculate(
                RiskContext(
                    asset_criticality={
                        "low": 20,
                        "medium": 50,
                        "high": 75,
                        "critical": 95,
                    }.get(str(asset.criticality), 50),
                    exposure=asset.exposure_score,
                    reachability=90 if asset.internet_exposed else 30,
                    vulnerability_severity=asset.risk_score,
                    vulnerability_confidence=asset.confidence * 100,
                    asset_owner=bool(asset.owner),
                    evidence_quality=asset.confidence * 100,
                )
            )
            asset.risk_score = result.overall_risk_score
        await db.commit()
        print(f"Recalculated risk for {len(assets)} tenant-owned asset(s).")


async def refresh_attack_paths() -> None:
    async with SessionLocal() as db:
        organizations = list((await db.scalars(select(Organization))).all())
        total = 0
        for organization in organizations:
            total += len(await AttackPathAnalysisService(db).analyze(organization.id))
        await db.commit()
        print(f"Generated {total} bounded candidate path(s) for review.")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("task", choices=["sync-feeds", "recalculate-risk", "refresh-attack-paths"])
    task = parser.parse_args().task
    asyncio.run(
        {
            "sync-feeds": sync_feeds,
            "recalculate-risk": recalculate_risk,
            "refresh-attack-paths": refresh_attack_paths,
        }[task]()
    )


if __name__ == "__main__":
    main()
