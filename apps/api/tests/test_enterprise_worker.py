from datetime import datetime, timezone

import pytest
from sqlalchemy import select

from cyberaudit import enterprise_worker
from cyberaudit.enterprise_models import EnterpriseRisk, Incident, KnowledgeNode, SecurityEvent
from cyberaudit.models import Organization


async def _organization(db, slug: str) -> Organization:
    organization = Organization(name=f"Tenant {slug}", slug=slug)
    db.add(organization)
    await db.flush()
    return organization


@pytest.mark.asyncio
async def test_rebuild_enterprise_knowledge_projects_incidents_and_risks(
    worker_session_factory, monkeypatch
):
    monkeypatch.setattr(enterprise_worker, "SessionLocal", worker_session_factory)
    async with worker_session_factory() as db:
        organization = await _organization(db, "knowledge-tenant")
        db.add(
            Incident(
                organization_id=organization.id,
                reference="INC-1",
                title="Suspicious login",
                severity="high",
                status="open",
                simulated=True,
            )
        )
        db.add(
            EnterpriseRisk(
                organization_id=organization.id,
                reference="RISK-1",
                title="Unpatched host",
                description="Synthetic risk",
                risk_type="technical",
                category="vulnerability",
                residual_score=4.2,
            )
        )
        await db.commit()
        organization_id = organization.id

    await enterprise_worker._rebuild_enterprise_knowledge(organization_id)

    async with worker_session_factory() as db:
        nodes = list(
            (
                await db.scalars(
                    select(KnowledgeNode).where(KnowledgeNode.organization_id == organization_id)
                )
            ).all()
        )
    node_types = {node.node_type for node in nodes}
    assert node_types == {"incident", "risk"}
    incident_node = next(node for node in nodes if node.node_type == "incident")
    assert incident_node.label == "Suspicious login"
    assert incident_node.facts["severity"] == "high"


@pytest.mark.asyncio
async def test_rebuild_enterprise_knowledge_updates_existing_nodes(
    worker_session_factory, monkeypatch
):
    monkeypatch.setattr(enterprise_worker, "SessionLocal", worker_session_factory)
    async with worker_session_factory() as db:
        organization = await _organization(db, "knowledge-update-tenant")
        incident = Incident(
            organization_id=organization.id,
            reference="INC-2",
            title="Initial title",
            severity="low",
            status="open",
            simulated=True,
        )
        db.add(incident)
        await db.commit()
        organization_id = organization.id
        incident_id = incident.id

    await enterprise_worker._rebuild_enterprise_knowledge(organization_id)

    async with worker_session_factory() as db:
        incident = await db.get(Incident, incident_id)
        incident.title = "Escalated title"
        incident.severity = "critical"
        await db.commit()

    await enterprise_worker._rebuild_enterprise_knowledge(organization_id)

    async with worker_session_factory() as db:
        node = await db.scalar(
            select(KnowledgeNode).where(
                KnowledgeNode.organization_id == organization_id,
                KnowledgeNode.node_type == "incident",
                KnowledgeNode.source_id == incident_id,
            )
        )
    assert node.label == "Escalated title"
    assert node.facts["severity"] == "critical"


@pytest.mark.asyncio
async def test_process_security_event_runs_detection_on_sqlite(worker_session_factory, monkeypatch):
    monkeypatch.setattr(enterprise_worker, "SessionLocal", worker_session_factory)
    async with worker_session_factory() as db:
        organization = await _organization(db, "detection-tenant")
        event = SecurityEvent(
            organization_id=organization.id,
            source="demo",
            external_id="evt-worker-1",
            event_type="authentication.failed",
            severity="medium",
            occurred_at=datetime.now(timezone.utc),
            summary="Synthetic event",
            normalized={"count": 1},
            content_hash="b" * 64,
        )
        db.add(event)
        await db.commit()
        event_id = event.id

    # sqlite is not postgresql, so tenant-context bootstrap from the resource
    # is skipped; the actor must still load the event and run detection.
    await enterprise_worker._process_security_event(event_id)


@pytest.mark.asyncio
async def test_process_security_event_returns_when_event_is_missing(
    worker_session_factory, monkeypatch
):
    monkeypatch.setattr(enterprise_worker, "SessionLocal", worker_session_factory)
    await enterprise_worker._process_security_event("00000000-0000-0000-0000-000000000000")
