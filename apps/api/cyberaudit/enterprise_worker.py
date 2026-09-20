"""Isolated defensive workers for the enterprise domains.

Actors receive identifiers only, load tenant context from PostgreSQL and never
perform network calls or execute user-provided code.
"""

from __future__ import annotations

import asyncio

import dramatiq
from sqlalchemy import select

from cyberaudit.db import SessionLocal
from cyberaudit.enterprise_models import (
    EnterpriseRisk,
    Incident,
    KnowledgeNode,
    SecurityEvent,
)
from cyberaudit.enterprise_services import DetectionEngine
from cyberaudit.queue import broker as _configured_broker  # noqa: F401
from cyberaudit.rls import set_tenant_context, set_tenant_context_from_resource


@dramatiq.actor(queue_name="cyberaudit.soc", max_retries=2, time_limit=60_000)
def process_security_event(event_id: str) -> None:
    asyncio.run(_process_security_event(event_id))


async def _process_security_event(event_id: str) -> None:
    async with SessionLocal() as db:
        if db.get_bind().dialect.name == "postgresql":
            if not await set_tenant_context_from_resource(db, "security_event", event_id):
                return
        event = await db.get(SecurityEvent, event_id)
        if not event:
            return
        await DetectionEngine().evaluate(db, event.organization_id, event)
        await db.commit()


@dramatiq.actor(queue_name="cyberaudit.knowledge", max_retries=1, time_limit=120_000)
def rebuild_enterprise_knowledge(organization_id: str) -> None:
    asyncio.run(_rebuild_enterprise_knowledge(organization_id))


async def _rebuild_enterprise_knowledge(organization_id: str) -> None:
    async with SessionLocal() as db:
        await set_tenant_context(db, organization_id)
        incidents = list(
            (
                await db.scalars(
                    select(Incident).where(Incident.organization_id == organization_id)
                )
            ).all()
        )
        risks = list(
            (
                await db.scalars(
                    select(EnterpriseRisk).where(EnterpriseRisk.organization_id == organization_id)
                )
            ).all()
        )
        projections = [
            (
                "incident",
                record.id,
                record.title,
                {"severity": record.severity, "status": record.status},
            )
            for record in incidents
        ] + [
            (
                "risk",
                record.id,
                record.title,
                {"residual_score": record.residual_score, "status": record.status},
            )
            for record in risks
        ]
        for source_type, source_id, label, facts in projections:
            node = await db.scalar(
                select(KnowledgeNode).where(
                    KnowledgeNode.organization_id == organization_id,
                    KnowledgeNode.node_type == source_type,
                    KnowledgeNode.source_id == source_id,
                )
            )
            if node:
                node.label = label
                node.facts = facts
            else:
                db.add(
                    KnowledgeNode(
                        organization_id=organization_id,
                        node_type=source_type,
                        source_id=source_id,
                        label=label,
                        facts=facts,
                        source_references=[f"{source_type}:{source_id}"],
                        confidence=1,
                    )
                )
        await db.commit()
