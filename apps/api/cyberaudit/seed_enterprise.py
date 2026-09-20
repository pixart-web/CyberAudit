"""Deterministic, synthetic demonstration data for Phases 7–9."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from cyberaudit.db import SessionLocal
from cyberaudit.enterprise_models import (
    ControlFramework,
    DetectionAlert,
    DetectionRule,
    EnterpriseRisk,
    FrameworkControlMapping,
    Incident,
    IncidentTimelineEntry,
    KnowledgeEdge,
    KnowledgeNode,
    ResponsePlaybook,
    RiskTreatmentPlan,
    SecurityEvent,
    ThreatIndicator,
    ThreatIntelFeed,
    UnifiedControl,
)
from cyberaudit.enterprise_services import SUPPORTED_FRAMEWORKS, alert_fingerprint, normalize_event
from cyberaudit.models import Organization, Permission, Role, User

ENTERPRISE_PERMISSIONS = [
    "soc.read",
    "events.read",
    "events.ingest",
    "detections.read",
    "detections.manage",
    "incidents.read",
    "incidents.manage",
    "cases.read",
    "cases.manage",
    "threat_intel.read",
    "threat_intel.manage",
    "hunts.read",
    "hunts.manage",
    "playbooks.read",
    "playbooks.manage",
    "security_data.read",
    "purple_team.read",
    "purple_team.manage",
    "grc.read",
    "governance.read",
    "governance.manage",
    "frameworks.read",
    "frameworks.manage",
    "controls.read",
    "controls.manage",
    "enterprise_risks.read",
    "enterprise_risks.manage",
    "grc_evidence.read",
    "grc_evidence.manage",
    "grc_exceptions.read",
    "grc_exceptions.request",
    "grc_exceptions.review",
    "knowledge_graph.read",
    "knowledge_graph.manage",
    "ai_assistant.read",
    "ai_assistant.use",
]


async def seed() -> None:
    async with SessionLocal() as db:
        organization = await db.scalar(
            select(Organization).where(Organization.slug == "cyberaudit-demo")
        )
        user = await db.scalar(select(User).where(User.email == "admin@cyberaudit.local"))
        if not organization or not user:
            raise RuntimeError("Run the base seed before seed-enterprise")

        permissions: dict[str, Permission] = {}
        for code in ENTERPRISE_PERMISSIONS:
            permission = await db.scalar(select(Permission).where(Permission.code == code))
            if not permission:
                permission = Permission(code=code, description=code.replace(".", " ").title())
                db.add(permission)
                await db.flush()
            permissions[code] = permission
        roles = list(
            (
                await db.scalars(
                    select(Role).where(
                        Role.name.in_(["Administrator", "Auditor", "Reviewer", "Client"])
                    )
                )
            ).all()
        )
        for role in roles:
            allowed = ENTERPRISE_PERMISSIONS
            if role.name == "Auditor":
                allowed = [
                    code
                    for code in ENTERPRISE_PERMISSIONS
                    if code not in {"frameworks.manage", "grc_exceptions.review"}
                ]
            elif role.name == "Reviewer":
                allowed = [
                    code
                    for code in ENTERPRISE_PERMISSIONS
                    if code.endswith(".read")
                    or code
                    in {
                        "incidents.manage",
                        "cases.manage",
                        "grc_exceptions.review",
                        "ai_assistant.use",
                    }
                ]
            elif role.name == "Client":
                allowed = [
                    "soc.read",
                    "incidents.read",
                    "grc.read",
                    "controls.read",
                    "enterprise_risks.read",
                ]
            current = {permission.code for permission in role.permissions}
            for code in allowed:
                if code not in current:
                    role.permissions.append(permissions[code])

        rule = await db.scalar(
            select(DetectionRule).where(
                DetectionRule.organization_id == organization.id,
                DetectionRule.code == "DEMO.AUTH.FAILURES",
            )
        )
        if not rule:
            rule = DetectionRule(
                organization_id=organization.id,
                code="DEMO.AUTH.FAILURES",
                name="[SIMULADO] Falhas de autenticação repetidas",
                description="Deteção determinística sobre eventos sintéticos.",
                severity="high",
                event_types=["authentication.failed"],
                conditions={"count": {"gte": 5}},
                mitre_techniques=["T1110"],
                owner_id=user.id,
                approved_by=user.id,
                approved_at=datetime.now(timezone.utc),
            )
            db.add(rule)
            await db.flush()
        normalized, content_hash = normalize_event(
            {"action": "login", "outcome": "failure", "username": "demo-user", "count": 7}
        )
        event = await db.scalar(
            select(SecurityEvent).where(
                SecurityEvent.organization_id == organization.id,
                SecurityEvent.source == "cyberaudit.synthetic",
                SecurityEvent.external_id == "phase7-event-001",
            )
        )
        if not event:
            event = SecurityEvent(
                organization_id=organization.id,
                source="cyberaudit.synthetic",
                external_id="phase7-event-001",
                event_type="authentication.failed",
                severity="medium",
                occurred_at=datetime.now(timezone.utc) - timedelta(minutes=25),
                actor_ref="demo-user",
                source_ip="10.10.10.20",
                summary="[SIMULADO] Sete falhas de autenticação no laboratório",
                normalized=normalized,
                labels=["simulated", "laboratory"],
                content_hash=content_hash,
                trusted=True,
            )
            db.add(event)
            await db.flush()
        fingerprint = alert_fingerprint(organization.id, rule.id, event)
        alert = await db.scalar(
            select(DetectionAlert).where(
                DetectionAlert.organization_id == organization.id,
                DetectionAlert.fingerprint == fingerprint,
            )
        )
        if not alert:
            alert = DetectionAlert(
                organization_id=organization.id,
                rule_id=rule.id,
                event_id=event.id,
                title=rule.name,
                severity="high",
                confidence=0.9,
                fingerprint=fingerprint,
                reasons=["Synthetic event matched approved demo rule"],
                mitre_techniques=["T1110"],
                first_seen_at=event.occurred_at,
                last_seen_at=event.occurred_at,
            )
            db.add(alert)
            await db.flush()
        incident = await db.scalar(
            select(Incident).where(
                Incident.organization_id == organization.id,
                Incident.reference == "INC-DEMO-001",
            )
        )
        if not incident:
            incident = Incident(
                organization_id=organization.id,
                reference="INC-DEMO-001",
                title="[SIMULADO] Atividade de autenticação anómala",
                description="Incidente fictício criado apenas para demonstração.",
                severity="high",
                status="investigating",
                owner_id=user.id,
                risk_score=8,
                simulated=True,
            )
            db.add(incident)
            await db.flush()
            alert.incident_id = incident.id
            db.add(
                IncidentTimelineEntry(
                    organization_id=organization.id,
                    incident_id=incident.id,
                    event_id=event.id,
                    entry_type="detection",
                    occurred_at=event.occurred_at,
                    title="[SIMULADO] Deteção associada",
                    source="cyberaudit.synthetic",
                    source_references=[f"event:{event.id}", f"alert:{alert.id}"],
                    created_by=user.id,
                )
            )
        feed = await db.scalar(
            select(ThreatIntelFeed).where(
                ThreatIntelFeed.organization_id == organization.id,
                ThreatIntelFeed.name == "CyberAudit Synthetic Intel",
            )
        )
        if not feed:
            feed = ThreatIntelFeed(
                organization_id=organization.id,
                name="CyberAudit Synthetic Intel",
                provider="CyberAudit Demo",
                source_type="embedded",
                trust_level="synthetic",
            )
            db.add(feed)
            await db.flush()
            db.add(
                ThreatIndicator(
                    organization_id=organization.id,
                    feed_id=feed.id,
                    indicator_type="ip",
                    display_value="192.0.2.44",
                    value_hash="c4ad67b4d6206a9582d0f4f772c4645bb4b5087184031f6f42b71ca31cc700e4",
                    confidence=0.5,
                    labels=["simulated", "documentation-range"],
                    references=["https://example.invalid/cyberaudit-demo-ioc"],
                )
            )
        playbook = await db.scalar(
            select(ResponsePlaybook).where(
                ResponsePlaybook.organization_id == organization.id,
                ResponsePlaybook.code == "DEMO.AUTH.REVIEW",
            )
        )
        if not playbook:
            db.add(
                ResponsePlaybook(
                    organization_id=organization.id,
                    code="DEMO.AUTH.REVIEW",
                    name="Revisão manual de autenticação",
                    description="Checklist defensiva sem ações automáticas.",
                    trigger_types=["authentication.failed"],
                    steps=[
                        {"type": "assign", "role": "Reviewer"},
                        {"type": "checklist", "text": "Validar contexto do evento"},
                        {"type": "document", "text": "Registar conclusão"},
                    ],
                    approval_required=True,
                    automatic_execution=False,
                    approved_by=user.id,
                )
            )

        frameworks: dict[str, ControlFramework] = {}
        for code, name in SUPPORTED_FRAMEWORKS.items():
            framework = await db.scalar(
                select(ControlFramework).where(
                    ControlFramework.organization_id == organization.id,
                    ControlFramework.code == code,
                )
            )
            if not framework:
                framework = ControlFramework(
                    organization_id=organization.id,
                    code=code,
                    name=name,
                    version="demo-2026",
                    description="Referencial demonstrativo; conteúdo normativo não incluído.",
                )
                db.add(framework)
                await db.flush()
            frameworks[code] = framework
        control = await db.scalar(
            select(UnifiedControl).where(
                UnifiedControl.organization_id == organization.id,
                UnifiedControl.code == "CA-IAM-001",
            )
        )
        if not control:
            control = UnifiedControl(
                organization_id=organization.id,
                code="CA-IAM-001",
                title="Autenticação multifator",
                description="Aplicar MFA proporcional ao risco.",
                domain="Identity and Access Management",
                owner_id=user.id,
                status="approved",
                maturity_level=3,
                implementation_status="partially_implemented",
                tags=["identity", "mfa"],
            )
            db.add(control)
            await db.flush()
            for code, external_id in (
                ("ISO27001", "A.5-demo"),
                ("NIS2", "Art.21-demo"),
                ("NIST-CSF", "PR.AA-demo"),
            ):
                db.add(
                    FrameworkControlMapping(
                        organization_id=organization.id,
                        framework_id=frameworks[code].id,
                        control_id=control.id,
                        external_control_id=external_id,
                        external_title="Mapeamento demonstrativo",
                        rationale="Equivalência apenas para demonstração; requer validação GRC.",
                    )
                )
        risk = await db.scalar(
            select(EnterpriseRisk).where(
                EnterpriseRisk.organization_id == organization.id,
                EnterpriseRisk.reference == "RISK-DEMO-001",
            )
        )
        if not risk:
            risk = EnterpriseRisk(
                organization_id=organization.id,
                reference="RISK-DEMO-001",
                title="[SIMULADO] Acesso sem MFA",
                description="Risco sintético para demonstrar o registo empresarial.",
                risk_type="cyber",
                category="identity",
                owner_id=user.id,
                likelihood=4,
                impact=5,
                inherent_score=20,
                control_effectiveness=0.5,
                residual_score=10,
                appetite=6,
                treatment_strategy="mitigate",
            )
            db.add(risk)
            await db.flush()
            db.add(
                RiskTreatmentPlan(
                    organization_id=organization.id,
                    risk_id=risk.id,
                    title="Expandir MFA",
                    description="Plano demonstrativo sujeito a aprovação humana.",
                    owner_id=user.id,
                    target_residual_score=4,
                    actions=[{"title": "Validar cobertura", "status": "planned"}],
                    progress=20,
                )
            )
        incident_node = await _node(
            db,
            organization.id,
            "incident",
            incident.id,
            incident.title,
            {"severity": incident.severity, "status": incident.status, "simulated": True},
        )
        risk_node = await _node(
            db,
            organization.id,
            "risk",
            risk.id,
            risk.title,
            {"residual_score": risk.residual_score, "status": risk.status, "simulated": True},
        )
        edge = await db.scalar(
            select(KnowledgeEdge).where(
                KnowledgeEdge.organization_id == organization.id,
                KnowledgeEdge.source_node_id == incident_node.id,
                KnowledgeEdge.edge_type == "informs",
                KnowledgeEdge.target_node_id == risk_node.id,
            )
        )
        if not edge:
            db.add(
                KnowledgeEdge(
                    organization_id=organization.id,
                    source_node_id=incident_node.id,
                    target_node_id=risk_node.id,
                    edge_type="informs",
                    facts={"basis": "synthetic_demo"},
                    source_references=[f"incident:{incident.id}", f"risk:{risk.id}"],
                    confidence=0.8,
                    inferred=False,
                )
            )
        await db.commit()


async def _node(
    db,
    organization_id: str,
    node_type: str,
    source_id: str,
    label: str,
    facts: dict,
) -> KnowledgeNode:
    node = await db.scalar(
        select(KnowledgeNode).where(
            KnowledgeNode.organization_id == organization_id,
            KnowledgeNode.node_type == node_type,
            KnowledgeNode.source_id == source_id,
        )
    )
    if not node:
        node = KnowledgeNode(
            organization_id=organization_id,
            node_type=node_type,
            source_id=source_id,
            label=label,
            facts=facts,
            source_references=[f"{node_type}:{source_id}"],
            confidence=1,
        )
        db.add(node)
        await db.flush()
    return node


if __name__ == "__main__":
    asyncio.run(seed())
