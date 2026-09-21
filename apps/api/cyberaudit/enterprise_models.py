"""Enterprise domains for SOC (Phase 7), GRC (Phase 8) and AI assistance (Phase 9).

The models deliberately keep every business record tenant-bound.  Automation
records describe decisions and recommendations only; they do not contain an
execution primitive.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from cyberaudit.db import Base


def uuid4() -> str:
    return str(uuid.uuid4())


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class EnterpriseMixin:
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid4)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


# Phase 7 — SOC, Detection and Incident Response


class SecurityEvent(Base, EnterpriseMixin):
    __tablename__ = "security_events"
    __table_args__ = (UniqueConstraint("organization_id", "source", "external_id"),)
    source: Mapped[str] = mapped_column(String(120))
    external_id: Mapped[str] = mapped_column(String(255))
    event_type: Mapped[str] = mapped_column(String(120), index=True)
    severity: Mapped[str] = mapped_column(String(20), default="info", index=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    actor_ref: Mapped[str | None] = mapped_column(String(255))
    asset_id: Mapped[str | None] = mapped_column(ForeignKey("assets.id"), index=True)
    source_ip: Mapped[str | None] = mapped_column(String(45))
    destination_ip: Mapped[str | None] = mapped_column(String(45))
    summary: Mapped[str] = mapped_column(String(500))
    normalized: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    labels: Mapped[list[str]] = mapped_column(JSON, default=list)
    content_hash: Mapped[str] = mapped_column(String(64), index=True)
    trusted: Mapped[bool] = mapped_column(Boolean, default=False)


class DetectionRule(Base, EnterpriseMixin):
    __tablename__ = "detection_rules"
    __table_args__ = (UniqueConstraint("organization_id", "code", "version"),)
    code: Mapped[str] = mapped_column(String(120))
    version: Mapped[int] = mapped_column(Integer, default=1)
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(20), default="medium")
    event_types: Mapped[list[str]] = mapped_column(JSON, default=list)
    conditions: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    mitre_techniques: Mapped[list[str]] = mapped_column(JSON, default=list)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    owner_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    approved_by: Mapped[str | None] = mapped_column(ForeignKey("users.id"))
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class DetectionAlert(Base, EnterpriseMixin):
    __tablename__ = "detection_alerts"
    __table_args__ = (UniqueConstraint("organization_id", "fingerprint"),)
    rule_id: Mapped[str] = mapped_column(ForeignKey("detection_rules.id"), index=True)
    event_id: Mapped[str] = mapped_column(ForeignKey("security_events.id"), index=True)
    incident_id: Mapped[str | None] = mapped_column(String(36), index=True)
    title: Mapped[str] = mapped_column(String(300))
    severity: Mapped[str] = mapped_column(String(20), index=True)
    status: Mapped[str] = mapped_column(String(30), default="open", index=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    fingerprint: Mapped[str] = mapped_column(String(64))
    reasons: Mapped[list[str]] = mapped_column(JSON, default=list)
    mitre_techniques: Mapped[list[str]] = mapped_column(JSON, default=list)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    occurrence_count: Mapped[int] = mapped_column(Integer, default=1)


class ThreatIntelFeed(Base, EnterpriseMixin):
    __tablename__ = "threat_intel_feeds"
    __table_args__ = (UniqueConstraint("organization_id", "name"),)
    name: Mapped[str] = mapped_column(String(180))
    provider: Mapped[str] = mapped_column(String(180))
    source_type: Mapped[str] = mapped_column(String(60), default="manual")
    trust_level: Mapped[str] = mapped_column(String(30), default="unverified")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(String(500))
    configuration: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class ThreatIndicator(Base, EnterpriseMixin):
    __tablename__ = "threat_indicators"
    __table_args__ = (UniqueConstraint("organization_id", "indicator_type", "value_hash"),)
    feed_id: Mapped[str | None] = mapped_column(ForeignKey("threat_intel_feeds.id"))
    indicator_type: Mapped[str] = mapped_column(String(40), index=True)
    display_value: Mapped[str] = mapped_column(String(500))
    value_hash: Mapped[str] = mapped_column(String(64))
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    severity: Mapped[str] = mapped_column(String(20), default="medium")
    status: Mapped[str] = mapped_column(String(30), default="active")
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    valid_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    labels: Mapped[list[str]] = mapped_column(JSON, default=list)
    references: Mapped[list[str]] = mapped_column(JSON, default=list)


class Incident(Base, EnterpriseMixin):
    __tablename__ = "incidents"
    __table_args__ = (UniqueConstraint("organization_id", "reference"),)
    reference: Mapped[str] = mapped_column(String(50))
    title: Mapped[str] = mapped_column(String(300))
    description: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(20), default="medium", index=True)
    status: Mapped[str] = mapped_column(String(40), default="open", index=True)
    category: Mapped[str] = mapped_column(String(100), default="security_event")
    owner_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"))
    engagement_id: Mapped[str | None] = mapped_column(ForeignKey("engagements.id"))
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    contained_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    business_impact: Mapped[str] = mapped_column(Text, default="")
    risk_score: Mapped[float] = mapped_column(Float, default=0)
    simulated: Mapped[bool] = mapped_column(Boolean, default=False)


class CaseRecord(Base, EnterpriseMixin):
    __tablename__ = "case_records"
    __table_args__ = (UniqueConstraint("organization_id", "reference"),)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"), index=True)
    reference: Mapped[str] = mapped_column(String(50))
    title: Mapped[str] = mapped_column(String(300))
    status: Mapped[str] = mapped_column(String(30), default="open")
    lead_investigator_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"))
    members: Mapped[list[str]] = mapped_column(JSON, default=list)
    hypothesis: Mapped[str] = mapped_column(Text, default="")
    conclusions: Mapped[str] = mapped_column(Text, default="")
    legal_hold: Mapped[bool] = mapped_column(Boolean, default=False)


class IncidentTimelineEntry(Base, EnterpriseMixin):
    __tablename__ = "incident_timeline_entries"
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"), index=True)
    case_id: Mapped[str | None] = mapped_column(ForeignKey("case_records.id"))
    event_id: Mapped[str | None] = mapped_column(ForeignKey("security_events.id"))
    entry_type: Mapped[str] = mapped_column(String(60))
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    title: Mapped[str] = mapped_column(String(300))
    description: Mapped[str] = mapped_column(Text, default="")
    source: Mapped[str] = mapped_column(String(120))
    source_references: Mapped[list[str]] = mapped_column(JSON, default=list)
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    immutable: Mapped[bool] = mapped_column(Boolean, default=True)


class ThreatHunt(Base, EnterpriseMixin):
    __tablename__ = "threat_hunts"
    name: Mapped[str] = mapped_column(String(240))
    hypothesis: Mapped[str] = mapped_column(Text)
    query: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(30), default="draft")
    owner_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    time_from: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    time_until: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    result_count: Mapped[int] = mapped_column(Integer, default=0)
    findings: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)


class ResponsePlaybook(Base, EnterpriseMixin):
    __tablename__ = "response_playbooks"
    __table_args__ = (UniqueConstraint("organization_id", "code", "version"),)
    code: Mapped[str] = mapped_column(String(120))
    version: Mapped[int] = mapped_column(Integer, default=1)
    name: Mapped[str] = mapped_column(String(240))
    description: Mapped[str] = mapped_column(Text, default="")
    trigger_types: Mapped[list[str]] = mapped_column(JSON, default=list)
    steps: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    approval_required: Mapped[bool] = mapped_column(Boolean, default=True)
    automatic_execution: Mapped[bool] = mapped_column(Boolean, default=False)
    approved_by: Mapped[str | None] = mapped_column(ForeignKey("users.id"))


class SecurityDataObject(Base, EnterpriseMixin):
    __tablename__ = "security_data_objects"
    object_type: Mapped[str] = mapped_column(String(80), index=True)
    source: Mapped[str] = mapped_column(String(120))
    storage_key: Mapped[str] = mapped_column(String(500))
    content_hash: Mapped[str] = mapped_column(String(64))
    content_type: Mapped[str] = mapped_column(String(120))
    size_bytes: Mapped[int] = mapped_column(Integer)
    retention_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    encrypted: Mapped[bool] = mapped_column(Boolean, default=True)
    immutable: Mapped[bool] = mapped_column(Boolean, default=True)
    classification: Mapped[str] = mapped_column(String(40), default="restricted")
    data_metadata: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict)


class PurpleTeamExercise(Base, EnterpriseMixin):
    __tablename__ = "purple_team_exercises"
    name: Mapped[str] = mapped_column(String(240))
    engagement_id: Mapped[str] = mapped_column(ForeignKey("engagements.id"))
    status: Mapped[str] = mapped_column(String(30), default="planned")
    mitre_techniques: Mapped[list[str]] = mapped_column(JSON, default=list)
    detection_rule_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    scope_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    outcomes: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    simulated_only: Mapped[bool] = mapped_column(Boolean, default=True)


# Phase 8 — Governance, Risk and Compliance


class ControlFramework(Base, EnterpriseMixin):
    __tablename__ = "control_frameworks"
    __table_args__ = (UniqueConstraint("organization_id", "code", "version"),)
    code: Mapped[str] = mapped_column(String(80))
    name: Mapped[str] = mapped_column(String(200))
    version: Mapped[str] = mapped_column(String(40))
    framework_type: Mapped[str] = mapped_column(String(60), default="compliance")
    description: Mapped[str] = mapped_column(Text, default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    source_reference: Mapped[str | None] = mapped_column(String(500))


class UnifiedControl(Base, EnterpriseMixin):
    __tablename__ = "unified_controls"
    __table_args__ = (UniqueConstraint("organization_id", "code"),)
    code: Mapped[str] = mapped_column(String(80))
    title: Mapped[str] = mapped_column(String(300))
    description: Mapped[str] = mapped_column(Text)
    domain: Mapped[str] = mapped_column(String(120), index=True)
    objective: Mapped[str] = mapped_column(Text, default="")
    owner_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"))
    status: Mapped[str] = mapped_column(String(30), default="draft")
    maturity_level: Mapped[int] = mapped_column(Integer, default=0)
    implementation_status: Mapped[str] = mapped_column(String(40), default="not_implemented")
    review_frequency_days: Mapped[int] = mapped_column(Integer, default=365)
    next_review_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    tags: Mapped[list[str]] = mapped_column(JSON, default=list)


class FrameworkControlMapping(Base, EnterpriseMixin):
    __tablename__ = "framework_control_mappings"
    __table_args__ = (UniqueConstraint("organization_id", "framework_id", "external_control_id"),)
    framework_id: Mapped[str] = mapped_column(ForeignKey("control_frameworks.id"), index=True)
    control_id: Mapped[str] = mapped_column(ForeignKey("unified_controls.id"), index=True)
    external_control_id: Mapped[str] = mapped_column(String(120))
    external_title: Mapped[str] = mapped_column(String(300))
    mapping_type: Mapped[str] = mapped_column(String(30), default="equivalent")
    confidence: Mapped[float] = mapped_column(Float, default=1)
    rationale: Mapped[str] = mapped_column(Text, default="")


class GovernancePolicy(Base, EnterpriseMixin):
    __tablename__ = "governance_policies"
    __table_args__ = (UniqueConstraint("organization_id", "code", "version"),)
    code: Mapped[str] = mapped_column(String(80))
    version: Mapped[int] = mapped_column(Integer, default=1)
    title: Mapped[str] = mapped_column(String(300))
    policy_type: Mapped[str] = mapped_column(String(80), default="policy")
    status: Mapped[str] = mapped_column(String(30), default="draft")
    content: Mapped[str] = mapped_column(Text)
    owner_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    approved_by: Mapped[str | None] = mapped_column(ForeignKey("users.id"))
    effective_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    review_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    control_ids: Mapped[list[str]] = mapped_column(JSON, default=list)


class EnterpriseRisk(Base, EnterpriseMixin):
    __tablename__ = "enterprise_risks"
    __table_args__ = (UniqueConstraint("organization_id", "reference"),)
    reference: Mapped[str] = mapped_column(String(60))
    title: Mapped[str] = mapped_column(String(300))
    description: Mapped[str] = mapped_column(Text)
    risk_type: Mapped[str] = mapped_column(String(60), index=True)
    category: Mapped[str] = mapped_column(String(100))
    status: Mapped[str] = mapped_column(String(30), default="open", index=True)
    owner_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"))
    asset_id: Mapped[str | None] = mapped_column(ForeignKey("assets.id"))
    third_party: Mapped[str | None] = mapped_column(String(240))
    likelihood: Mapped[float] = mapped_column(Float, default=1)
    impact: Mapped[float] = mapped_column(Float, default=1)
    inherent_score: Mapped[float] = mapped_column(Float, default=1)
    control_effectiveness: Mapped[float] = mapped_column(Float, default=0)
    residual_score: Mapped[float] = mapped_column(Float, default=1)
    appetite: Mapped[float] = mapped_column(Float, default=5)
    treatment_strategy: Mapped[str] = mapped_column(String(30), default="mitigate")
    review_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    accepted_by: Mapped[str | None] = mapped_column(ForeignKey("users.id"))
    accepted_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class RiskTreatmentPlan(Base, EnterpriseMixin):
    __tablename__ = "risk_treatment_plans"
    risk_id: Mapped[str] = mapped_column(ForeignKey("enterprise_risks.id"), index=True)
    title: Mapped[str] = mapped_column(String(300))
    description: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(30), default="planned")
    owner_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    target_residual_score: Mapped[float] = mapped_column(Float, default=1)
    actions: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    progress: Mapped[int] = mapped_column(Integer, default=0)


class ControlAssessment(Base, EnterpriseMixin):
    __tablename__ = "control_assessments"
    control_id: Mapped[str] = mapped_column(ForeignKey("unified_controls.id"), index=True)
    assessor_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    status: Mapped[str] = mapped_column(String(30), default="planned")
    result: Mapped[str] = mapped_column(String(40), default="not_assessed")
    effectiveness: Mapped[float] = mapped_column(Float, default=0)
    tested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    next_test_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    notes: Mapped[str] = mapped_column(Text, default="")
    evidence_ids: Mapped[list[str]] = mapped_column(JSON, default=list)


class GrcEvidenceLink(Base, EnterpriseMixin):
    __tablename__ = "grc_evidence_links"
    evidence_id: Mapped[str] = mapped_column(ForeignKey("evidence.id"), index=True)
    subject_type: Mapped[str] = mapped_column(String(60), index=True)
    subject_id: Mapped[str] = mapped_column(String(36), index=True)
    purpose: Mapped[str] = mapped_column(String(200))
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    valid_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    verified_by: Mapped[str | None] = mapped_column(ForeignKey("users.id"))
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class GrcException(Base, EnterpriseMixin):
    __tablename__ = "grc_exceptions"
    subject_type: Mapped[str] = mapped_column(String(60))
    subject_id: Mapped[str] = mapped_column(String(36))
    reason: Mapped[str] = mapped_column(Text)
    compensating_controls: Mapped[list[str]] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(30), default="pending")
    requested_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    reviewed_by: Mapped[str | None] = mapped_column(ForeignKey("users.id"))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    review_notes: Mapped[str] = mapped_column(Text, default="")


# Phase 9 — Knowledge Graph and explainable, advisory-only AI


class KnowledgeNode(Base, EnterpriseMixin):
    __tablename__ = "knowledge_nodes"
    __table_args__ = (UniqueConstraint("organization_id", "node_type", "source_id"),)
    node_type: Mapped[str] = mapped_column(String(80), index=True)
    source_id: Mapped[str] = mapped_column(String(36), index=True)
    label: Mapped[str] = mapped_column(String(300))
    facts: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    source_references: Mapped[list[str]] = mapped_column(JSON, default=list)
    confidence: Mapped[float] = mapped_column(Float, default=1)
    indexed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class KnowledgeEdge(Base, EnterpriseMixin):
    __tablename__ = "knowledge_edges"
    __table_args__ = (
        UniqueConstraint("organization_id", "source_node_id", "edge_type", "target_node_id"),
    )
    source_node_id: Mapped[str] = mapped_column(ForeignKey("knowledge_nodes.id"), index=True)
    target_node_id: Mapped[str] = mapped_column(ForeignKey("knowledge_nodes.id"), index=True)
    edge_type: Mapped[str] = mapped_column(String(100), index=True)
    facts: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    source_references: Mapped[list[str]] = mapped_column(JSON, default=list)
    confidence: Mapped[float] = mapped_column(Float, default=1)
    inferred: Mapped[bool] = mapped_column(Boolean, default=False)


class AiAssistantRequest(Base, EnterpriseMixin):
    __tablename__ = "ai_assistant_requests"
    service: Mapped[str] = mapped_column(String(80), index=True)
    question: Mapped[str] = mapped_column(Text)
    context_selector: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(30), default="completed")
    provider: Mapped[str] = mapped_column(String(80), default="deterministic")
    model: Mapped[str] = mapped_column(String(120), default="grounded-rules-v1")
    response: Mapped[str] = mapped_column(Text)
    facts: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    inferences: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    citations: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    confidence: Mapped[float] = mapped_column(Float, default=0)
    limitations: Mapped[list[str]] = mapped_column(JSON, default=list)
    reproducibility_key: Mapped[str] = mapped_column(String(64), index=True)
    requested_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    contains_sensitive_data: Mapped[bool] = mapped_column(Boolean, default=False)
    action_executed: Mapped[bool] = mapped_column(Boolean, default=False)


class AiProviderPolicy(Base, EnterpriseMixin):
    __tablename__ = "ai_provider_policies"
    __table_args__ = (UniqueConstraint("organization_id", "provider_code"),)
    provider_code: Mapped[str] = mapped_column(String(80))
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    allowed_services: Mapped[list[str]] = mapped_column(JSON, default=list)
    allowed_data_classifications: Mapped[list[str]] = mapped_column(JSON, default=list)
    data_residency: Mapped[str | None] = mapped_column(String(80))
    retention_allowed: Mapped[bool] = mapped_column(Boolean, default=False)
    human_review_required: Mapped[bool] = mapped_column(Boolean, default=True)
    configuration: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
