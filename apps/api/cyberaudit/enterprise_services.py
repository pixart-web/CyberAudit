"""Deterministic enterprise services with no offensive or autonomous actions."""

from __future__ import annotations

import hashlib
import json
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from cyberaudit.enterprise_models import (
    AiAssistantRequest,
    DetectionAlert,
    DetectionRule,
    EnterpriseRisk,
    KnowledgeNode,
    SecurityEvent,
)
from cyberaudit.models import User

SECRET_PATTERNS = (
    re.compile(r"(?i)(authorization|api[-_]?key|token|password)\s*[:=]\s*\S+"),
    re.compile(r"(?i)bearer\s+[a-z0-9._~+/=-]+"),
)
ALLOWED_EVENT_FIELDS = {
    "action",
    "outcome",
    "protocol",
    "port",
    "username",
    "resource",
    "process_name",
    "country",
    "count",
}
INCIDENT_TRANSITIONS = {
    "open": {"triaged", "cancelled"},
    "triaged": {"investigating", "contained", "cancelled"},
    "investigating": {"contained", "resolved", "cancelled"},
    "contained": {"investigating", "resolved"},
    "resolved": {"closed", "investigating"},
    "closed": set(),
    "cancelled": set(),
}


def sanitize_text(value: str, maximum: int = 10_000) -> str:
    sanitized = value[:maximum].replace("\x00", "")
    for pattern in SECRET_PATTERNS:
        sanitized = pattern.sub("[REDACTED]", sanitized)
    return sanitized


def normalize_event(payload: dict[str, Any]) -> tuple[dict[str, Any], str]:
    """Keep an explicit event schema and return a stable content hash."""
    normalized: dict[str, Any] = {}
    for key, value in payload.items():
        if key not in ALLOWED_EVENT_FIELDS:
            continue
        if isinstance(value, str):
            normalized[key] = sanitize_text(value, 1000)
        elif isinstance(value, (bool, int, float)) or value is None:
            normalized[key] = value
    canonical = json.dumps(normalized, sort_keys=True, separators=(",", ":"))
    return normalized, hashlib.sha256(canonical.encode()).hexdigest()


def alert_fingerprint(organization_id: str, rule_id: str, event: SecurityEvent) -> str:
    identity = "|".join(
        [
            organization_id,
            rule_id,
            event.event_type,
            event.asset_id or "",
            event.actor_ref or "",
            event.source_ip or "",
        ]
    )
    return hashlib.sha256(identity.encode()).hexdigest()


class DetectionEngine:
    """Allowlisted equality/threshold matcher; it never evaluates user code."""

    OPERATORS = {"equals", "contains", "gte", "in"}

    @classmethod
    def validate_conditions(cls, conditions: dict[str, Any]) -> None:
        for field, expression in conditions.items():
            if field not in ALLOWED_EVENT_FIELDS:
                raise ValueError(f"Unsupported detection field: {field}")
            if not isinstance(expression, dict) or len(expression) != 1:
                raise ValueError("Each detection condition needs one operator")
            operator = next(iter(expression))
            if operator not in cls.OPERATORS:
                raise ValueError(f"Unsupported detection operator: {operator}")

    @classmethod
    def matches(cls, rule: DetectionRule, event: SecurityEvent) -> bool:
        if not rule.enabled or (rule.event_types and event.event_type not in rule.event_types):
            return False
        cls.validate_conditions(rule.conditions)
        for field, expression in rule.conditions.items():
            actual = event.normalized.get(field)
            operator, expected = next(iter(expression.items()))
            if operator == "equals" and actual != expected:
                return False
            if operator == "contains" and str(expected).lower() not in str(actual).lower():
                return False
            if operator == "gte" and (
                not isinstance(actual, (int, float)) or float(actual) < float(expected)
            ):
                return False
            if operator == "in" and actual not in expected:
                return False
        return True

    async def evaluate(
        self, db: AsyncSession, organization_id: str, event: SecurityEvent
    ) -> list[DetectionAlert]:
        rules = list(
            (
                await db.scalars(
                    select(DetectionRule).where(
                        DetectionRule.organization_id == organization_id,
                        DetectionRule.enabled.is_(True),
                    )
                )
            ).all()
        )
        alerts: list[DetectionAlert] = []
        for rule in rules:
            if not self.matches(rule, event):
                continue
            fingerprint = alert_fingerprint(organization_id, rule.id, event)
            existing = await db.scalar(
                select(DetectionAlert).where(
                    DetectionAlert.organization_id == organization_id,
                    DetectionAlert.fingerprint == fingerprint,
                )
            )
            if existing:
                existing.last_seen_at = event.occurred_at
                existing.occurrence_count += 1
                alerts.append(existing)
                continue
            alert = DetectionAlert(
                organization_id=organization_id,
                rule_id=rule.id,
                event_id=event.id,
                title=rule.name,
                severity=rule.severity,
                confidence=0.8,
                fingerprint=fingerprint,
                reasons=[f"Matched approved rule {rule.code} v{rule.version}"],
                mitre_techniques=rule.mitre_techniques,
                first_seen_at=event.occurred_at,
                last_seen_at=event.occurred_at,
            )
            db.add(alert)
            alerts.append(alert)
        await db.flush()
        return alerts


def validate_incident_transition(current: str, requested: str) -> None:
    if requested not in INCIDENT_TRANSITIONS.get(current, set()):
        raise ValueError(f"Invalid incident transition: {current} -> {requested}")


def calculate_residual_risk(
    likelihood: float, impact: float, control_effectiveness: float
) -> tuple[float, float]:
    if not 1 <= likelihood <= 5 or not 1 <= impact <= 5:
        raise ValueError("Likelihood and impact must be between 1 and 5")
    if not 0 <= control_effectiveness <= 1:
        raise ValueError("Control effectiveness must be between 0 and 1")
    inherent = round(likelihood * impact, 2)
    residual = round(inherent * (1 - control_effectiveness), 2)
    return inherent, residual


SUPPORTED_FRAMEWORKS = {
    "ISO27001": "ISO/IEC 27001",
    "ISO27002": "ISO/IEC 27002",
    "NIS2": "NIS2",
    "DORA": "DORA",
    "PCI-DSS": "PCI DSS",
    "CIS": "CIS Controls",
    "NIST-CSF": "NIST Cybersecurity Framework",
    "NIST-800-53": "NIST SP 800-53",
    "SOC2": "SOC 2",
    "GDPR": "GDPR control state",
}


class AiQuestion(BaseModel):
    model_config = ConfigDict(extra="forbid")
    service: Literal[
        "explanation",
        "recommendation",
        "investigation",
        "compliance",
        "risk",
        "report",
        "evidence_summary",
        "attack_path",
        "executive",
    ]
    question: str = Field(min_length=3, max_length=4000)
    context_selector: dict[str, Any] = Field(default_factory=dict)


@dataclass(frozen=True)
class GroundedAnswer:
    response: str
    facts: list[dict[str, Any]]
    inferences: list[dict[str, Any]]
    citations: list[dict[str, Any]]
    confidence: float
    limitations: list[str]
    reproducibility_key: str


class AiProvider(ABC):
    code: str

    @abstractmethod
    async def answer(
        self, question: AiQuestion, sources: list[KnowledgeNode]
    ) -> GroundedAnswer: ...


class DeterministicGroundedProvider(AiProvider):
    """Offline provider used until an organization explicitly approves a model."""

    code = "deterministic"

    async def answer(self, question: AiQuestion, sources: list[KnowledgeNode]) -> GroundedAnswer:
        ordered = sorted(sources, key=lambda item: (item.node_type, item.source_id))
        citations = [
            {
                "node_id": item.id,
                "source_type": item.node_type,
                "source_id": item.source_id,
                "references": item.source_references,
            }
            for item in ordered[:20]
        ]
        facts = [
            {"source_id": item.source_id, "label": item.label, "facts": item.facts}
            for item in ordered[:20]
        ]
        if not facts:
            response = "Não existem fontes internas suficientes para responder com segurança."
            confidence = 0.0
            limitations = ["Sem fontes no Knowledge Graph para o contexto selecionado."]
        else:
            response = (
                f"Síntese determinística baseada em {len(facts)} fonte(s) interna(s). "
                "Requer validação humana antes de qualquer decisão."
            )
            confidence = min(0.9, sum(item.confidence for item in ordered[:20]) / len(facts))
            limitations = [
                "Resposta gerada sem modelo externo.",
                "Não executa ações e pode omitir contexto não indexado.",
            ]
        canonical = json.dumps(
            {
                "service": question.service,
                "question": question.question,
                "sources": [item.id for item in ordered[:20]],
            },
            sort_keys=True,
        )
        return GroundedAnswer(
            response=response,
            facts=facts,
            inferences=[],
            citations=citations,
            confidence=round(confidence, 2),
            limitations=limitations,
            reproducibility_key=hashlib.sha256(canonical.encode()).hexdigest(),
        )


class AiAssistantService:
    def __init__(self, db: AsyncSession, provider: AiProvider | None = None):
        self.db = db
        self.provider = provider or DeterministicGroundedProvider()

    async def ask(
        self, organization_id: str, user: User, question: AiQuestion
    ) -> AiAssistantRequest:
        selector = question.context_selector
        requested_ids = selector.get("source_ids", [])
        if not isinstance(requested_ids, list) or len(requested_ids) > 100:
            raise ValueError("source_ids must be a list with at most 100 entries")
        statement = select(KnowledgeNode).where(KnowledgeNode.organization_id == organization_id)
        if requested_ids:
            statement = statement.where(KnowledgeNode.source_id.in_(requested_ids))
        sources = list((await self.db.scalars(statement.limit(100))).all())
        answer = await self.provider.answer(question, sources)
        record = AiAssistantRequest(
            organization_id=organization_id,
            service=question.service,
            question=sanitize_text(question.question, 4000),
            context_selector=selector,
            provider=self.provider.code,
            response=answer.response,
            facts=answer.facts,
            inferences=answer.inferences,
            citations=answer.citations,
            confidence=answer.confidence,
            limitations=answer.limitations,
            reproducibility_key=answer.reproducibility_key,
            requested_by=user.id,
            completed_at=datetime.now(timezone.utc),
            action_executed=False,
        )
        self.db.add(record)
        await self.db.flush()
        return record


async def enterprise_metrics(db: AsyncSession, organization_id: str) -> dict[str, int | float]:
    events = await db.scalar(
        select(func.count())
        .select_from(SecurityEvent)
        .where(SecurityEvent.organization_id == organization_id)
    )
    open_alerts = await db.scalar(
        select(func.count())
        .select_from(DetectionAlert)
        .where(
            DetectionAlert.organization_id == organization_id,
            DetectionAlert.status == "open",
        )
    )
    open_risks = await db.scalar(
        select(func.count())
        .select_from(EnterpriseRisk)
        .where(
            EnterpriseRisk.organization_id == organization_id,
            EnterpriseRisk.status == "open",
        )
    )
    average_risk = await db.scalar(
        select(func.avg(EnterpriseRisk.residual_score)).where(
            EnterpriseRisk.organization_id == organization_id
        )
    )
    return {
        "events": events or 0,
        "open_alerts": open_alerts or 0,
        "open_risks": open_risks or 0,
        "average_residual_risk": round(float(average_risk or 0), 2),
    }
