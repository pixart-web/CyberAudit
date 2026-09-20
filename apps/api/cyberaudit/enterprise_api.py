"""REST API for CyberAudit enterprise Phases 7–9."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, inspect, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from cyberaudit.audit import write_audit
from cyberaudit.db import get_db
from cyberaudit.enterprise_models import (
    AiAssistantRequest,
    CaseRecord,
    ControlAssessment,
    ControlFramework,
    DetectionAlert,
    DetectionRule,
    EnterpriseRisk,
    FrameworkControlMapping,
    GovernancePolicy,
    GrcEvidenceLink,
    GrcException,
    Incident,
    IncidentTimelineEntry,
    KnowledgeEdge,
    KnowledgeNode,
    PurpleTeamExercise,
    ResponsePlaybook,
    RiskTreatmentPlan,
    SecurityDataObject,
    SecurityEvent,
    ThreatHunt,
    ThreatIndicator,
    ThreatIntelFeed,
    UnifiedControl,
)
from cyberaudit.enterprise_services import (
    SUPPORTED_FRAMEWORKS,
    AiAssistantService,
    AiQuestion,
    DetectionEngine,
    calculate_residual_risk,
    enterprise_metrics,
    normalize_event,
    sanitize_text,
    validate_incident_transition,
)
from cyberaudit.models import Evidence, User
from cyberaudit.security import require_permission

router = APIRouter(prefix="/api/v1", tags=["enterprise"])


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class EventPayload(StrictModel):
    source: str = Field(min_length=2, max_length=120)
    external_id: str = Field(min_length=1, max_length=255)
    event_type: str = Field(min_length=2, max_length=120)
    severity: Literal["info", "low", "medium", "high", "critical"] = "info"
    occurred_at: datetime
    actor_ref: str | None = Field(default=None, max_length=255)
    asset_id: str | None = None
    source_ip: str | None = Field(default=None, max_length=45)
    destination_ip: str | None = Field(default=None, max_length=45)
    summary: str = Field(min_length=2, max_length=500)
    data: dict[str, Any] = Field(default_factory=dict)
    labels: list[str] = Field(default_factory=list, max_length=50)


class DetectionRulePayload(StrictModel):
    code: str = Field(pattern=r"^[A-Z0-9_.-]+$", max_length=120)
    name: str = Field(min_length=3, max_length=200)
    description: str = Field(default="", max_length=5000)
    severity: Literal["low", "medium", "high", "critical"] = "medium"
    event_types: list[str] = Field(default_factory=list, max_length=50)
    conditions: dict[str, Any]
    mitre_techniques: list[str] = Field(default_factory=list, max_length=50)
    enabled: bool = True


class IncidentPayload(StrictModel):
    title: str = Field(min_length=3, max_length=300)
    description: str = Field(default="", max_length=10_000)
    severity: Literal["low", "medium", "high", "critical"] = "medium"
    category: str = Field(default="security_event", max_length=100)
    owner_id: str | None = None
    engagement_id: str | None = None
    business_impact: str = Field(default="", max_length=10_000)
    alert_ids: list[str] = Field(default_factory=list, max_length=100)
    simulated: bool = False


class StatePayload(StrictModel):
    status: str = Field(min_length=2, max_length=40)
    note: str = Field(default="", max_length=5000)


class HuntPayload(StrictModel):
    name: str = Field(min_length=3, max_length=240)
    hypothesis: str = Field(min_length=10, max_length=10_000)
    query: dict[str, Any] = Field(default_factory=dict)
    time_from: datetime
    time_until: datetime


class PlaybookPayload(StrictModel):
    code: str = Field(pattern=r"^[A-Z0-9_.-]+$", max_length=120)
    name: str = Field(min_length=3, max_length=240)
    description: str = Field(default="", max_length=5000)
    trigger_types: list[str] = Field(default_factory=list, max_length=50)
    steps: list[dict[str, Any]] = Field(default_factory=list, max_length=100)
    approval_required: bool = True


class FrameworkPayload(StrictModel):
    code: str
    version: str = Field(min_length=1, max_length=40)
    description: str = Field(default="", max_length=5000)


class ControlPayload(StrictModel):
    code: str = Field(pattern=r"^[A-Z0-9_.-]+$", max_length=80)
    title: str = Field(min_length=3, max_length=300)
    description: str = Field(min_length=3, max_length=10_000)
    domain: str = Field(min_length=2, max_length=120)
    objective: str = Field(default="", max_length=5000)
    owner_id: str | None = None
    review_frequency_days: int = Field(default=365, ge=1, le=3650)
    tags: list[str] = Field(default_factory=list, max_length=50)


class RiskPayload(StrictModel):
    title: str = Field(min_length=3, max_length=300)
    description: str = Field(min_length=3, max_length=10_000)
    risk_type: Literal["enterprise", "business", "it", "cyber", "third_party", "asset"]
    category: str = Field(min_length=2, max_length=100)
    owner_id: str | None = None
    asset_id: str | None = None
    third_party: str | None = Field(default=None, max_length=240)
    likelihood: float = Field(ge=1, le=5)
    impact: float = Field(ge=1, le=5)
    control_effectiveness: float = Field(default=0, ge=0, le=1)
    appetite: float = Field(default=5, ge=0, le=25)
    treatment_strategy: Literal["avoid", "mitigate", "transfer", "accept"] = "mitigate"
    review_at: datetime | None = None


class PolicyPayload(StrictModel):
    code: str = Field(pattern=r"^[A-Z0-9_.-]+$", max_length=80)
    title: str = Field(min_length=3, max_length=300)
    content: str = Field(min_length=10, max_length=100_000)
    policy_type: str = Field(default="policy", max_length=80)
    effective_at: datetime | None = None
    expires_at: datetime | None = None
    review_at: datetime | None = None
    control_ids: list[str] = Field(default_factory=list, max_length=500)


class ControlMappingPayload(StrictModel):
    framework_id: str
    control_id: str
    external_control_id: str = Field(min_length=1, max_length=120)
    external_title: str = Field(min_length=2, max_length=300)
    mapping_type: Literal["equivalent", "partial", "supports"] = "equivalent"
    confidence: float = Field(default=1, ge=0, le=1)
    rationale: str = Field(default="", max_length=5000)


class ControlAssessmentPayload(StrictModel):
    control_id: str
    result: Literal[
        "not_assessed", "effective", "partially_effective", "ineffective", "not_applicable"
    ] = "not_assessed"
    effectiveness: float = Field(default=0, ge=0, le=1)
    tested_at: datetime | None = None
    next_test_at: datetime | None = None
    notes: str = Field(default="", max_length=10_000)
    evidence_ids: list[str] = Field(default_factory=list, max_length=500)


class EvidenceLinkPayload(StrictModel):
    evidence_id: str
    subject_type: Literal[
        "control", "risk", "engagement", "finding", "asset", "application", "incident"
    ]
    subject_id: str
    purpose: str = Field(min_length=3, max_length=200)
    valid_until: datetime | None = None


class GrcExceptionPayload(StrictModel):
    subject_type: Literal["control", "risk", "policy", "framework"]
    subject_id: str
    reason: str = Field(min_length=10, max_length=10_000)
    compensating_controls: list[str] = Field(default_factory=list, max_length=100)
    expires_at: datetime


class ReviewPayload(StrictModel):
    notes: str = Field(default="", max_length=5000)


class TreatmentPayload(StrictModel):
    title: str = Field(min_length=3, max_length=300)
    description: str = Field(min_length=3, max_length=10_000)
    owner_id: str
    due_at: datetime | None = None
    target_residual_score: float = Field(ge=0, le=25)
    actions: list[dict[str, Any]] = Field(default_factory=list, max_length=100)


class KnowledgeNodePayload(StrictModel):
    node_type: Literal[
        "asset",
        "identity",
        "cloud",
        "application",
        "api",
        "vulnerability",
        "finding",
        "incident",
        "risk",
        "control",
        "evidence",
        "compliance",
    ]
    source_id: str
    label: str = Field(min_length=2, max_length=300)
    facts: dict[str, Any] = Field(default_factory=dict)
    source_references: list[str] = Field(default_factory=list, max_length=100)
    confidence: float = Field(default=1, ge=0, le=1)


def serialize(record: Any) -> dict[str, Any]:
    return {
        attribute.key: getattr(record, attribute.key)
        for attribute in inspect(record).mapper.column_attrs
    }


async def page(
    db: AsyncSession,
    model: Any,
    organization_id: str,
    *,
    page_number: int,
    page_size: int,
    q: str | None = None,
    search_fields: tuple[Any, ...] = (),
    extra: tuple[Any, ...] = (),
) -> dict[str, Any]:
    where = [model.organization_id == organization_id, *extra]
    if q and search_fields:
        where.append(or_(*(field.ilike(f"%{q}%") for field in search_fields)))
    total = await db.scalar(select(func.count()).select_from(model).where(*where))
    rows = list(
        (
            await db.scalars(
                select(model)
                .where(*where)
                .order_by(model.created_at.desc())
                .offset((page_number - 1) * page_size)
                .limit(page_size)
            )
        ).all()
    )
    return {
        "items": [serialize(row) for row in rows],
        "total": total or 0,
        "page": page_number,
        "page_size": page_size,
    }


def pagination(
    page_number: int = Query(default=1, alias="page", ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
) -> tuple[int, int]:
    return page_number, page_size


@router.get("/soc/dashboard")
async def soc_dashboard(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("soc.read")),
):
    metrics = await enterprise_metrics(db, user.organization_id)
    incidents = await db.scalar(
        select(func.count())
        .select_from(Incident)
        .where(
            Incident.organization_id == user.organization_id,
            Incident.status.not_in(["closed", "cancelled"]),
        )
    )
    critical = await db.scalar(
        select(func.count())
        .select_from(DetectionAlert)
        .where(
            DetectionAlert.organization_id == user.organization_id,
            DetectionAlert.severity == "critical",
            DetectionAlert.status == "open",
        )
    )
    return {**metrics, "open_incidents": incidents or 0, "critical_alerts": critical or 0}


@router.get("/security-events")
async def list_events(
    q: str | None = Query(default=None, max_length=200),
    pagination_values: tuple[int, int] = Depends(pagination),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("events.read")),
):
    return await page(
        db,
        SecurityEvent,
        user.organization_id,
        page_number=pagination_values[0],
        page_size=pagination_values[1],
        q=q,
        search_fields=(SecurityEvent.summary, SecurityEvent.event_type, SecurityEvent.source),
    )


@router.post("/security-events", status_code=201)
async def ingest_event(
    payload: EventPayload,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("events.ingest")),
):
    existing = await db.scalar(
        select(SecurityEvent).where(
            SecurityEvent.organization_id == user.organization_id,
            SecurityEvent.source == payload.source,
            SecurityEvent.external_id == payload.external_id,
        )
    )
    if existing:
        return {"event": serialize(existing), "alerts": [], "deduplicated": True}
    normalized, content_hash = normalize_event(payload.data)
    event = SecurityEvent(
        organization_id=user.organization_id,
        source=payload.source,
        external_id=payload.external_id,
        event_type=payload.event_type,
        severity=payload.severity,
        occurred_at=payload.occurred_at,
        actor_ref=payload.actor_ref,
        asset_id=payload.asset_id,
        source_ip=payload.source_ip,
        destination_ip=payload.destination_ip,
        summary=sanitize_text(payload.summary, 500),
        normalized=normalized,
        labels=payload.labels,
        content_hash=content_hash,
        trusted=False,
    )
    db.add(event)
    await db.flush()
    alerts = await DetectionEngine().evaluate(db, user.organization_id, event)
    await write_audit(
        db,
        user,
        "soc.event_ingested",
        "security_event",
        event.id,
        metadata={"source": event.source, "alerts": len(alerts)},
    )
    await db.commit()
    return {
        "event": serialize(event),
        "alerts": [serialize(alert) for alert in alerts],
        "deduplicated": False,
    }


@router.get("/detections/rules")
async def list_detection_rules(
    pagination_values: tuple[int, int] = Depends(pagination),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("detections.read")),
):
    return await page(
        db,
        DetectionRule,
        user.organization_id,
        page_number=pagination_values[0],
        page_size=pagination_values[1],
    )


@router.post("/detections/rules", status_code=201)
async def create_detection_rule(
    payload: DetectionRulePayload,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("detections.manage")),
):
    try:
        DetectionEngine.validate_conditions(payload.conditions)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    rule = DetectionRule(
        organization_id=user.organization_id,
        owner_id=user.id,
        **payload.model_dump(),
    )
    db.add(rule)
    await db.flush()
    await write_audit(db, user, "detection_rule.created", "detection_rule", rule.id)
    await db.commit()
    return serialize(rule)


@router.get("/detections/alerts")
async def list_alerts(
    status: str | None = Query(default=None, max_length=30),
    pagination_values: tuple[int, int] = Depends(pagination),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("detections.read")),
):
    extra = (DetectionAlert.status == status,) if status else ()
    return await page(
        db,
        DetectionAlert,
        user.organization_id,
        page_number=pagination_values[0],
        page_size=pagination_values[1],
        extra=extra,
    )


@router.get("/incidents")
async def list_incidents(
    q: str | None = Query(default=None, max_length=200),
    pagination_values: tuple[int, int] = Depends(pagination),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("incidents.read")),
):
    return await page(
        db,
        Incident,
        user.organization_id,
        page_number=pagination_values[0],
        page_size=pagination_values[1],
        q=q,
        search_fields=(Incident.title, Incident.reference),
    )


@router.post("/incidents", status_code=201)
async def create_incident(
    payload: IncidentPayload,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("incidents.manage")),
):
    count = await db.scalar(
        select(func.count())
        .select_from(Incident)
        .where(Incident.organization_id == user.organization_id)
    )
    incident = Incident(
        organization_id=user.organization_id,
        reference=f"INC-{(count or 0) + 1:06d}",
        title=payload.title,
        description=payload.description,
        severity=payload.severity,
        category=payload.category,
        owner_id=payload.owner_id or user.id,
        engagement_id=payload.engagement_id,
        business_impact=payload.business_impact,
        simulated=payload.simulated,
        risk_score={"low": 2, "medium": 5, "high": 8, "critical": 10}[payload.severity],
    )
    db.add(incident)
    await db.flush()
    for alert_id in payload.alert_ids:
        alert = await db.scalar(
            select(DetectionAlert).where(
                DetectionAlert.id == alert_id,
                DetectionAlert.organization_id == user.organization_id,
            )
        )
        if alert:
            alert.incident_id = incident.id
            alert.status = "investigating"
    timeline = IncidentTimelineEntry(
        organization_id=user.organization_id,
        incident_id=incident.id,
        entry_type="created",
        occurred_at=datetime.now(timezone.utc),
        title="Incidente criado",
        source="cyberaudit",
        created_by=user.id,
    )
    db.add(timeline)
    await write_audit(db, user, "incident.created", "incident", incident.id)
    await db.commit()
    return serialize(incident)


@router.get("/incidents/{incident_id}")
async def get_incident(
    incident_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("incidents.read")),
):
    incident = await db.scalar(
        select(Incident).where(
            Incident.id == incident_id, Incident.organization_id == user.organization_id
        )
    )
    if not incident:
        raise HTTPException(404, "Incident not found")
    timeline = list(
        (
            await db.scalars(
                select(IncidentTimelineEntry)
                .where(
                    IncidentTimelineEntry.incident_id == incident.id,
                    IncidentTimelineEntry.organization_id == user.organization_id,
                )
                .order_by(IncidentTimelineEntry.occurred_at)
            )
        ).all()
    )
    return {"incident": serialize(incident), "timeline": [serialize(item) for item in timeline]}


@router.post("/incidents/{incident_id}/transition")
async def transition_incident(
    incident_id: str,
    payload: StatePayload,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("incidents.manage")),
):
    incident = await db.scalar(
        select(Incident).where(
            Incident.id == incident_id, Incident.organization_id == user.organization_id
        )
    )
    if not incident:
        raise HTTPException(404, "Incident not found")
    try:
        validate_incident_transition(incident.status, payload.status)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    previous = incident.status
    incident.status = payload.status
    now = datetime.now(timezone.utc)
    if payload.status == "contained":
        incident.contained_at = now
    elif payload.status == "resolved":
        incident.resolved_at = now
    elif payload.status == "closed":
        incident.closed_at = now
    db.add(
        IncidentTimelineEntry(
            organization_id=user.organization_id,
            incident_id=incident.id,
            entry_type="state_changed",
            occurred_at=now,
            title=f"Estado alterado: {previous} → {payload.status}",
            description=payload.note,
            source="cyberaudit",
            created_by=user.id,
        )
    )
    await write_audit(
        db,
        user,
        "incident.state_changed",
        "incident",
        incident.id,
        metadata={"from": previous, "to": payload.status},
    )
    await db.commit()
    return serialize(incident)


@router.get("/cases")
async def list_cases(
    pagination_values: tuple[int, int] = Depends(pagination),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("cases.read")),
):
    return await page(
        db,
        CaseRecord,
        user.organization_id,
        page_number=pagination_values[0],
        page_size=pagination_values[1],
    )


@router.get("/iocs")
async def list_iocs(
    pagination_values: tuple[int, int] = Depends(pagination),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("threat_intel.read")),
):
    return await page(
        db,
        ThreatIndicator,
        user.organization_id,
        page_number=pagination_values[0],
        page_size=pagination_values[1],
    )


@router.get("/threat-intelligence/feeds")
async def list_threat_feeds(
    pagination_values: tuple[int, int] = Depends(pagination),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("threat_intel.read")),
):
    return await page(
        db,
        ThreatIntelFeed,
        user.organization_id,
        page_number=pagination_values[0],
        page_size=pagination_values[1],
    )


@router.get("/hunts")
async def list_hunts(
    pagination_values: tuple[int, int] = Depends(pagination),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("hunts.read")),
):
    return await page(
        db,
        ThreatHunt,
        user.organization_id,
        page_number=pagination_values[0],
        page_size=pagination_values[1],
    )


@router.post("/hunts", status_code=201)
async def create_hunt(
    payload: HuntPayload,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("hunts.manage")),
):
    allowed_query_fields = {"event_type", "severity", "source", "asset_id", "actor_ref"}
    if set(payload.query) - allowed_query_fields:
        raise HTTPException(422, "Unsupported hunt query field")
    hunt = ThreatHunt(
        organization_id=user.organization_id,
        owner_id=user.id,
        **payload.model_dump(),
    )
    db.add(hunt)
    await db.flush()
    await write_audit(db, user, "hunt.created", "threat_hunt", hunt.id)
    await db.commit()
    return serialize(hunt)


@router.get("/playbooks")
async def list_playbooks(
    pagination_values: tuple[int, int] = Depends(pagination),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("playbooks.read")),
):
    return await page(
        db,
        ResponsePlaybook,
        user.organization_id,
        page_number=pagination_values[0],
        page_size=pagination_values[1],
    )


@router.post("/playbooks", status_code=201)
async def create_playbook(
    payload: PlaybookPayload,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("playbooks.manage")),
):
    allowed_step_types = {"checklist", "notify", "assign", "request_approval", "document"}
    if any(step.get("type") not in allowed_step_types for step in payload.steps):
        raise HTTPException(422, "Playbooks accept only non-executing step types")
    playbook = ResponsePlaybook(
        organization_id=user.organization_id,
        automatic_execution=False,
        **payload.model_dump(),
    )
    db.add(playbook)
    await db.flush()
    await write_audit(db, user, "playbook.created", "response_playbook", playbook.id)
    await db.commit()
    return serialize(playbook)


@router.get("/security-data-lake")
async def list_data_objects(
    pagination_values: tuple[int, int] = Depends(pagination),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("security_data.read")),
):
    return await page(
        db,
        SecurityDataObject,
        user.organization_id,
        page_number=pagination_values[0],
        page_size=pagination_values[1],
    )


@router.get("/purple-team/exercises")
async def list_purple_exercises(
    pagination_values: tuple[int, int] = Depends(pagination),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("purple_team.read")),
):
    return await page(
        db,
        PurpleTeamExercise,
        user.organization_id,
        page_number=pagination_values[0],
        page_size=pagination_values[1],
    )


@router.get("/attack-graph/v3")
async def attack_graph_v3(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("attack_paths.read")),
):
    alerts = list(
        (
            await db.scalars(
                select(DetectionAlert)
                .where(DetectionAlert.organization_id == user.organization_id)
                .order_by(DetectionAlert.last_seen_at.desc())
                .limit(100)
            )
        ).all()
    )
    return {
        "version": "3.0",
        "nodes": [
            {
                "id": alert.id,
                "type": "detection",
                "label": alert.title,
                "severity": alert.severity,
                "confidence": alert.confidence,
            }
            for alert in alerts
        ],
        "edges": [],
        "limitations": ["Only evidence-backed detection nodes are projected."],
    }


@router.get("/risk/v3")
async def risk_v3(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("risk.read")),
):
    metrics = await enterprise_metrics(db, user.organization_id)
    return {
        "version": "3.0",
        "metrics": metrics,
        "method": "deterministic_evidence_weighted",
        "limitations": ["Risk scores support decisions and do not replace human review."],
    }


@router.get("/grc/dashboard")
async def grc_dashboard(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("grc.read")),
):
    controls = await db.scalar(
        select(func.count())
        .select_from(UnifiedControl)
        .where(UnifiedControl.organization_id == user.organization_id)
    )
    implemented = await db.scalar(
        select(func.count())
        .select_from(UnifiedControl)
        .where(
            UnifiedControl.organization_id == user.organization_id,
            UnifiedControl.implementation_status == "implemented",
        )
    )
    metrics = await enterprise_metrics(db, user.organization_id)
    return {
        **metrics,
        "controls": controls or 0,
        "implemented_controls": implemented or 0,
        "control_coverage": round((implemented or 0) * 100 / (controls or 1)),
    }


@router.get("/grc/frameworks")
async def list_frameworks(
    pagination_values: tuple[int, int] = Depends(pagination),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("frameworks.read")),
):
    return await page(
        db,
        ControlFramework,
        user.organization_id,
        page_number=pagination_values[0],
        page_size=pagination_values[1],
    )


@router.post("/grc/frameworks", status_code=201)
async def create_framework(
    payload: FrameworkPayload,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("frameworks.manage")),
):
    if payload.code not in SUPPORTED_FRAMEWORKS:
        raise HTTPException(422, "Unsupported framework code")
    framework = ControlFramework(
        organization_id=user.organization_id,
        code=payload.code,
        name=SUPPORTED_FRAMEWORKS[payload.code],
        version=payload.version,
        description=payload.description,
    )
    db.add(framework)
    await db.flush()
    await write_audit(db, user, "framework.created", "control_framework", framework.id)
    await db.commit()
    return serialize(framework)


@router.get("/grc/controls")
async def list_controls(
    q: str | None = Query(default=None, max_length=200),
    pagination_values: tuple[int, int] = Depends(pagination),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("controls.read")),
):
    return await page(
        db,
        UnifiedControl,
        user.organization_id,
        page_number=pagination_values[0],
        page_size=pagination_values[1],
        q=q,
        search_fields=(UnifiedControl.code, UnifiedControl.title, UnifiedControl.domain),
    )


@router.post("/grc/controls", status_code=201)
async def create_control(
    payload: ControlPayload,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("controls.manage")),
):
    control = UnifiedControl(organization_id=user.organization_id, **payload.model_dump())
    db.add(control)
    await db.flush()
    await write_audit(db, user, "control.created", "unified_control", control.id)
    await db.commit()
    return serialize(control)


@router.get("/grc/control-mappings")
async def list_control_mappings(
    pagination_values: tuple[int, int] = Depends(pagination),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("controls.read")),
):
    return await page(
        db,
        FrameworkControlMapping,
        user.organization_id,
        page_number=pagination_values[0],
        page_size=pagination_values[1],
    )


@router.post("/grc/control-mappings", status_code=201)
async def create_control_mapping(
    payload: ControlMappingPayload,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("controls.manage")),
):
    framework = await db.scalar(
        select(ControlFramework).where(
            ControlFramework.id == payload.framework_id,
            ControlFramework.organization_id == user.organization_id,
        )
    )
    control = await db.scalar(
        select(UnifiedControl).where(
            UnifiedControl.id == payload.control_id,
            UnifiedControl.organization_id == user.organization_id,
        )
    )
    if not framework or not control:
        raise HTTPException(404, "Framework or control not found")
    mapping = FrameworkControlMapping(organization_id=user.organization_id, **payload.model_dump())
    db.add(mapping)
    await db.flush()
    await write_audit(db, user, "control_mapping.created", "control_mapping", mapping.id)
    await db.commit()
    return serialize(mapping)


@router.get("/grc/control-assessments")
async def list_control_assessments(
    pagination_values: tuple[int, int] = Depends(pagination),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("controls.read")),
):
    return await page(
        db,
        ControlAssessment,
        user.organization_id,
        page_number=pagination_values[0],
        page_size=pagination_values[1],
    )


@router.post("/grc/control-assessments", status_code=201)
async def create_control_assessment(
    payload: ControlAssessmentPayload,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("controls.manage")),
):
    control = await db.scalar(
        select(UnifiedControl).where(
            UnifiedControl.id == payload.control_id,
            UnifiedControl.organization_id == user.organization_id,
        )
    )
    if not control:
        raise HTTPException(404, "Control not found")
    if payload.evidence_ids:
        evidence_count = await db.scalar(
            select(func.count())
            .select_from(Evidence)
            .where(
                Evidence.organization_id == user.organization_id,
                Evidence.id.in_(payload.evidence_ids),
            )
        )
        if evidence_count != len(set(payload.evidence_ids)):
            raise HTTPException(404, "One or more evidence records were not found")
    assessment = ControlAssessment(
        organization_id=user.organization_id,
        assessor_id=user.id,
        status="completed" if payload.result != "not_assessed" else "planned",
        **payload.model_dump(),
    )
    db.add(assessment)
    await db.flush()
    await write_audit(db, user, "control.assessed", "control_assessment", assessment.id)
    await db.commit()
    return serialize(assessment)


@router.get("/grc/risks")
async def list_risks(
    q: str | None = Query(default=None, max_length=200),
    pagination_values: tuple[int, int] = Depends(pagination),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("enterprise_risks.read")),
):
    return await page(
        db,
        EnterpriseRisk,
        user.organization_id,
        page_number=pagination_values[0],
        page_size=pagination_values[1],
        q=q,
        search_fields=(EnterpriseRisk.reference, EnterpriseRisk.title, EnterpriseRisk.category),
    )


@router.post("/grc/risks", status_code=201)
async def create_risk(
    payload: RiskPayload,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("enterprise_risks.manage")),
):
    count = await db.scalar(
        select(func.count())
        .select_from(EnterpriseRisk)
        .where(EnterpriseRisk.organization_id == user.organization_id)
    )
    inherent, residual = calculate_residual_risk(
        payload.likelihood, payload.impact, payload.control_effectiveness
    )
    risk = EnterpriseRisk(
        organization_id=user.organization_id,
        reference=f"RISK-{(count or 0) + 1:06d}",
        inherent_score=inherent,
        residual_score=residual,
        **payload.model_dump(),
    )
    db.add(risk)
    await db.flush()
    await write_audit(db, user, "risk.created", "enterprise_risk", risk.id)
    await db.commit()
    return serialize(risk)


@router.post("/grc/risks/{risk_id}/treatments", status_code=201)
async def create_treatment(
    risk_id: str,
    payload: TreatmentPayload,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("enterprise_risks.manage")),
):
    risk = await db.scalar(
        select(EnterpriseRisk).where(
            EnterpriseRisk.id == risk_id,
            EnterpriseRisk.organization_id == user.organization_id,
        )
    )
    if not risk:
        raise HTTPException(404, "Risk not found")
    treatment = RiskTreatmentPlan(
        organization_id=user.organization_id,
        risk_id=risk.id,
        **payload.model_dump(),
    )
    db.add(treatment)
    await db.flush()
    await write_audit(db, user, "risk_treatment.created", "risk_treatment", treatment.id)
    await db.commit()
    return serialize(treatment)


@router.get("/grc/policies")
async def list_policies(
    pagination_values: tuple[int, int] = Depends(pagination),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("governance.read")),
):
    return await page(
        db,
        GovernancePolicy,
        user.organization_id,
        page_number=pagination_values[0],
        page_size=pagination_values[1],
    )


@router.post("/grc/policies", status_code=201)
async def create_policy(
    payload: PolicyPayload,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("governance.manage")),
):
    if payload.control_ids:
        controls = await db.scalar(
            select(func.count())
            .select_from(UnifiedControl)
            .where(
                UnifiedControl.organization_id == user.organization_id,
                UnifiedControl.id.in_(payload.control_ids),
            )
        )
        if controls != len(set(payload.control_ids)):
            raise HTTPException(404, "One or more controls were not found")
    policy = GovernancePolicy(
        organization_id=user.organization_id,
        owner_id=user.id,
        status="draft",
        **payload.model_dump(),
    )
    db.add(policy)
    await db.flush()
    await write_audit(db, user, "governance_policy.created", "governance_policy", policy.id)
    await db.commit()
    return serialize(policy)


@router.get("/grc/evidence-links")
async def list_grc_evidence(
    pagination_values: tuple[int, int] = Depends(pagination),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("grc_evidence.read")),
):
    return await page(
        db,
        GrcEvidenceLink,
        user.organization_id,
        page_number=pagination_values[0],
        page_size=pagination_values[1],
    )


@router.post("/grc/evidence-links", status_code=201)
async def create_grc_evidence_link(
    payload: EvidenceLinkPayload,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("grc_evidence.manage")),
):
    evidence = await db.scalar(
        select(Evidence).where(
            Evidence.id == payload.evidence_id,
            Evidence.organization_id == user.organization_id,
        )
    )
    if not evidence:
        raise HTTPException(404, "Evidence not found")
    link = GrcEvidenceLink(
        organization_id=user.organization_id,
        **payload.model_dump(),
    )
    db.add(link)
    await db.flush()
    await write_audit(db, user, "grc_evidence.linked", "grc_evidence_link", link.id)
    await db.commit()
    return serialize(link)


@router.get("/grc/exceptions")
async def list_grc_exceptions(
    pagination_values: tuple[int, int] = Depends(pagination),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("grc_exceptions.read")),
):
    return await page(
        db,
        GrcException,
        user.organization_id,
        page_number=pagination_values[0],
        page_size=pagination_values[1],
    )


@router.post("/grc/exceptions", status_code=201)
async def create_grc_exception(
    payload: GrcExceptionPayload,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("grc_exceptions.request")),
):
    if payload.expires_at <= datetime.now(timezone.utc):
        raise HTTPException(422, "Exception expiry must be in the future")
    exception = GrcException(
        organization_id=user.organization_id,
        requested_by=user.id,
        **payload.model_dump(),
    )
    db.add(exception)
    await db.flush()
    await write_audit(db, user, "grc_exception.requested", "grc_exception", exception.id)
    await db.commit()
    return serialize(exception)


@router.post("/grc/exceptions/{exception_id}/approve")
async def approve_grc_exception(
    exception_id: str,
    payload: ReviewPayload,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("grc_exceptions.review")),
):
    exception = await db.scalar(
        select(GrcException).where(
            GrcException.id == exception_id,
            GrcException.organization_id == user.organization_id,
            GrcException.status == "pending",
        )
    )
    if not exception:
        raise HTTPException(404, "Pending exception not found")
    if exception.expires_at <= datetime.now(timezone.utc):
        exception.status = "expired"
        await db.commit()
        raise HTTPException(409, "Exception has expired")
    exception.status = "approved"
    exception.reviewed_by = user.id
    exception.reviewed_at = datetime.now(timezone.utc)
    exception.review_notes = payload.notes
    await write_audit(db, user, "grc_exception.approved", "grc_exception", exception.id)
    await db.commit()
    return serialize(exception)


@router.post("/grc/exceptions/{exception_id}/reject")
async def reject_grc_exception(
    exception_id: str,
    payload: ReviewPayload,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("grc_exceptions.review")),
):
    exception = await db.scalar(
        select(GrcException).where(
            GrcException.id == exception_id,
            GrcException.organization_id == user.organization_id,
            GrcException.status == "pending",
        )
    )
    if not exception:
        raise HTTPException(404, "Pending exception not found")
    exception.status = "rejected"
    exception.reviewed_by = user.id
    exception.reviewed_at = datetime.now(timezone.utc)
    exception.review_notes = payload.notes
    await write_audit(db, user, "grc_exception.rejected", "grc_exception", exception.id)
    await db.commit()
    return serialize(exception)


@router.get("/knowledge-graph")
async def knowledge_graph(
    node_type: str | None = Query(default=None, max_length=80),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("knowledge_graph.read")),
):
    where = [KnowledgeNode.organization_id == user.organization_id]
    if node_type:
        where.append(KnowledgeNode.node_type == node_type)
    nodes = list((await db.scalars(select(KnowledgeNode).where(*where).limit(500))).all())
    node_ids = [node.id for node in nodes]
    edges = (
        list(
            (
                await db.scalars(
                    select(KnowledgeEdge).where(
                        KnowledgeEdge.organization_id == user.organization_id,
                        KnowledgeEdge.source_node_id.in_(node_ids),
                        KnowledgeEdge.target_node_id.in_(node_ids),
                    )
                )
            ).all()
        )
        if node_ids
        else []
    )
    return {
        "nodes": [serialize(node) for node in nodes],
        "edges": [serialize(edge) for edge in edges],
    }


@router.get("/knowledge-nodes")
async def list_knowledge_nodes(
    node_type: str | None = Query(default=None, max_length=80),
    pagination_values: tuple[int, int] = Depends(pagination),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("knowledge_graph.read")),
):
    extra = (KnowledgeNode.node_type == node_type,) if node_type else ()
    return await page(
        db,
        KnowledgeNode,
        user.organization_id,
        page_number=pagination_values[0],
        page_size=pagination_values[1],
        extra=extra,
    )


@router.post("/knowledge-graph/nodes", status_code=201)
async def upsert_knowledge_node(
    payload: KnowledgeNodePayload,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("knowledge_graph.manage")),
):
    node = await db.scalar(
        select(KnowledgeNode).where(
            KnowledgeNode.organization_id == user.organization_id,
            KnowledgeNode.node_type == payload.node_type,
            KnowledgeNode.source_id == payload.source_id,
        )
    )
    if node:
        for key, value in payload.model_dump().items():
            setattr(node, key, value)
    else:
        node = KnowledgeNode(organization_id=user.organization_id, **payload.model_dump())
        db.add(node)
    await db.flush()
    await write_audit(db, user, "knowledge_node.upserted", "knowledge_node", node.id)
    await db.commit()
    return serialize(node)


@router.get("/ai/services")
async def ai_services(user: User = Depends(require_permission("ai_assistant.read"))):
    return {
        "services": [
            "explanation",
            "recommendation",
            "investigation",
            "compliance",
            "risk",
            "report",
            "evidence_summary",
            "attack_path",
            "executive",
        ],
        "provider": "deterministic",
        "autonomous_actions": False,
        "tenant": user.organization_id,
    }


@router.post("/ai/assist", status_code=201)
async def ai_assist(
    payload: AiQuestion,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("ai_assistant.use")),
):
    try:
        record = await AiAssistantService(db).ask(user.organization_id, user, payload)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    await write_audit(
        db,
        user,
        "ai.assistance_requested",
        "ai_assistant_request",
        record.id,
        metadata={"service": record.service, "provider": record.provider},
    )
    await db.commit()
    return serialize(record)


@router.get("/ai/requests")
async def list_ai_requests(
    pagination_values: tuple[int, int] = Depends(pagination),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("ai_assistant.read")),
):
    return await page(
        db,
        AiAssistantRequest,
        user.organization_id,
        page_number=pagination_values[0],
        page_size=pagination_values[1],
    )


@router.get("/enterprise/health")
async def enterprise_health(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("system_health.read")),
):
    checksum = hashlib.sha256(user.organization_id.encode()).hexdigest()[:12]
    return {
        "status": "ok",
        "modules": {
            "soc": "online",
            "grc": "online",
            "ai": "advisory_only",
            "connectors": "read_only",
            "connector_queue": "online",
            "graph_projection": "bounded",
            "risk_evaluation": "deterministic",
            "zero_trust": "deterministic",
            "identity": "online",
            "cloud": "online",
            "kubernetes": "online",
            "endpoints": "online",
            "mobile": "online",
        },
        "tenant_context": checksum,
    }
