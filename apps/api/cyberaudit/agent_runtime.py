"""CyberAgentRuntime and AgentToolGateway (Phase 10.3.5).

Specialized agents are configuration, not code: one shared runtime
(:class:`CyberAgentRuntime`) parameterized by an :class:`AgentDefinition` --
mission framing, allowed knowledge scopes and allowed tools -- rather than
ten duplicated chatbot wrappers.

Every tool call passes through :class:`AgentToolGateway`, which enforces, in
order: agent tool allowlist -> RBAC permission -> tenant match (every
handler filters by ``user.organization_id``) -> input validation ->
execution -> audit event. No agent, and no tool handler, ever executes a
shell command, arbitrary SQL, or reaches Docker/Kubernetes directly; tools
only read already-persisted, tenant-scoped rows.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cyberaudit.audit import write_audit
from cyberaudit.enterprise_models import Incident, KnowledgeNode
from cyberaudit.enterprise_services import (
    AiProvider,
    AiQuestion,
    DeterministicGroundedProvider,
    GroundedAnswer,
)
from cyberaudit.local_retrieval import DisabledEmbeddingBackend, LocalRetrievalService
from cyberaudit.models import Finding, Scope, User
from cyberaudit.redaction import redact_text
from cyberaudit.security import user_has_permission


class AgentToolError(RuntimeError):
    """Raised when a tool call is denied, unknown, or fails validation."""


@dataclass(frozen=True)
class AgentDefinition:
    code: str
    name: str
    mission: str
    service_literal: str
    knowledge_scopes: tuple[str, ...]
    allowed_tools: tuple[str, ...]


@dataclass(frozen=True)
class AgentTool:
    name: str
    required_permission: str
    input_model: type[BaseModel]
    handler: Callable[[AsyncSession, User, BaseModel], Awaitable[dict[str, Any]]]


@dataclass(frozen=True)
class AgentAnswer:
    agent_code: str
    correlation_id: str
    response: str
    facts: list[dict[str, Any]]
    citations: list[dict[str, Any]]
    confidence: float
    limitations: list[str]
    reproducibility_key: str
    required_human_approval: bool


# ---------------------------------------------------------------------------
# Tool input schemas and handlers -- read-only, bounded, tenant-scoped
# ---------------------------------------------------------------------------


class GetFindingInput(BaseModel):
    finding_id: str


async def _get_finding(db: AsyncSession, user: User, payload: BaseModel) -> dict[str, Any]:
    assert isinstance(payload, GetFindingInput)
    finding = await db.get(Finding, payload.finding_id)
    if not finding or finding.organization_id != user.organization_id:
        raise AgentToolError("Finding not found")
    return {
        "id": finding.id,
        "title": redact_text(finding.title, 240),
        "category": finding.category,
        "technical_severity": finding.technical_severity.value,
        "engagement_id": finding.engagement_id,
    }


class ListIncidentsInput(BaseModel):
    limit: int = 20


async def _list_incidents(db: AsyncSession, user: User, payload: BaseModel) -> dict[str, Any]:
    assert isinstance(payload, ListIncidentsInput)
    if not 1 <= payload.limit <= 100:
        raise AgentToolError("limit must be between 1 and 100")
    rows = list(
        (
            await db.scalars(
                select(Incident)
                .where(Incident.organization_id == user.organization_id)
                .order_by(Incident.detected_at.desc())
                .limit(payload.limit)
            )
        ).all()
    )
    return {
        "items": [
            {
                "id": row.id,
                "reference": row.reference,
                "severity": row.severity,
                "status": row.status,
            }
            for row in rows
        ]
    }


class GetEngagementScopeInput(BaseModel):
    engagement_id: str


async def _get_engagement_scope(db: AsyncSession, user: User, payload: BaseModel) -> dict[str, Any]:
    assert isinstance(payload, GetEngagementScopeInput)
    rows = list(
        (
            await db.scalars(
                select(Scope).where(
                    Scope.organization_id == user.organization_id,
                    Scope.engagement_id == payload.engagement_id,
                )
            )
        ).all()
    )
    return {
        "items": [
            {
                "id": row.id,
                "name": row.name,
                "status": row.status,
                "maximum_intensity": row.maximum_intensity.value,
            }
            for row in rows
        ]
    }


AGENT_TOOLS: dict[str, AgentTool] = {
    "get_finding": AgentTool("get_finding", "findings.read", GetFindingInput, _get_finding),
    "list_incidents": AgentTool(
        "list_incidents", "incidents.read", ListIncidentsInput, _list_incidents
    ),
    "get_engagement_scope": AgentTool(
        "get_engagement_scope", "scopes.read", GetEngagementScopeInput, _get_engagement_scope
    ),
}


class AgentToolGateway:
    """Enforces authorization and validation for every agent tool call."""

    def __init__(self, db: AsyncSession, tools: dict[str, AgentTool] | None = None):
        self.db = db
        self.tools = tools if tools is not None else AGENT_TOOLS

    async def invoke(
        self,
        agent: AgentDefinition,
        tool_name: str,
        user: User,
        raw_payload: dict[str, Any],
    ) -> dict[str, Any]:
        if tool_name not in agent.allowed_tools:
            raise AgentToolError(f"Agent {agent.code} is not permitted to use tool {tool_name}")
        tool = self.tools.get(tool_name)
        if tool is None:
            raise AgentToolError(f"Unknown tool: {tool_name}")
        if not user_has_permission(user, tool.required_permission):
            raise AgentToolError(f"Missing permission: {tool.required_permission}")
        try:
            payload = tool.input_model.model_validate(raw_payload)
        except ValidationError as exc:
            raise AgentToolError(f"Invalid input for tool {tool_name}: {exc}") from exc
        result = await tool.handler(self.db, user, payload)
        await write_audit(
            self.db,
            user,
            "agent.tool_invoked",
            "agent_tool",
            tool_name,
            metadata={"agent": agent.code, "tool": tool_name},
        )
        return result


# ---------------------------------------------------------------------------
# Agent catalog -- configuration, not duplicated implementations
# ---------------------------------------------------------------------------

AGENT_CATALOG: dict[str, AgentDefinition] = {
    "security_analyst": AgentDefinition(
        code="security_analyst",
        name="Security Analyst Agent",
        mission="Explain findings, exposure and attack surface using only recorded evidence.",
        service_literal="explanation",
        knowledge_scopes=("finding", "asset", "risk"),
        allowed_tools=("get_finding",),
    ),
    "soc_analyst": AgentDefinition(
        code="soc_analyst",
        name="SOC Analyst Agent",
        mission="Summarize security events and detections for triage.",
        service_literal="investigation",
        knowledge_scopes=("incident", "security_event"),
        allowed_tools=("list_incidents",),
    ),
    "incident_analyst": AgentDefinition(
        code="incident_analyst",
        name="Incident Analyst Agent",
        mission="Reconstruct incident timelines strictly from recorded evidence.",
        service_literal="investigation",
        knowledge_scopes=("incident",),
        allowed_tools=("list_incidents",),
    ),
    "identity_analyst": AgentDefinition(
        code="identity_analyst",
        name="Identity Analyst Agent",
        mission="Explain identity posture and privilege risk from recorded observations.",
        service_literal="explanation",
        knowledge_scopes=("identity",),
        allowed_tools=(),
    ),
    "cloud_analyst": AgentDefinition(
        code="cloud_analyst",
        name="Cloud Analyst Agent",
        mission="Explain cloud posture from recorded, imported data only.",
        service_literal="explanation",
        knowledge_scopes=("cloud",),
        allowed_tools=(),
    ),
    "risk_analyst": AgentDefinition(
        code="risk_analyst",
        name="Risk Analyst Agent",
        mission="Explain deterministic risk scores; never invents a score.",
        service_literal="risk",
        knowledge_scopes=("risk",),
        allowed_tools=("get_finding",),
    ),
    "grc_analyst": AgentDefinition(
        code="grc_analyst",
        name="GRC Analyst Agent",
        mission="Explain compliance gaps against recorded control assessments.",
        service_literal="compliance",
        knowledge_scopes=("control",),
        allowed_tools=(),
    ),
    "knowledge_analyst": AgentDefinition(
        code="knowledge_analyst",
        name="Knowledge Analyst Agent",
        mission="Answer knowledge-graph queries across every recorded node type.",
        service_literal="explanation",
        knowledge_scopes=(),
        allowed_tools=("get_engagement_scope",),
    ),
    "report_agent": AgentDefinition(
        code="report_agent",
        name="Report Agent",
        mission="Draft report sections strictly grounded in recorded evidence.",
        service_literal="report",
        knowledge_scopes=("finding", "risk", "control"),
        allowed_tools=("get_finding",),
    ),
    "remediation_advisor": AgentDefinition(
        code="remediation_advisor",
        name="Remediation Advisor",
        mission="Propose remediation steps for a finding; never executes them.",
        service_literal="recommendation",
        knowledge_scopes=("finding",),
        allowed_tools=("get_finding",),
    ),
}


class CyberAgentRuntime:
    """Shared runtime: builds a grounded answer scoped to one agent's mission."""

    def __init__(
        self,
        db: AsyncSession,
        provider: AiProvider | None = None,
        retrieval: LocalRetrievalService | None = None,
    ):
        self.db = db
        self.provider = provider or DeterministicGroundedProvider()
        # Offline-safe default: lexical-only ranking, no local model required.
        self.retrieval = retrieval or LocalRetrievalService(DisabledEmbeddingBackend())

    async def ask(
        self,
        agent_code: str,
        user: User,
        question: str,
        *,
        source_ids: list[str] | None = None,
    ) -> AgentAnswer:
        agent = AGENT_CATALOG.get(agent_code)
        if agent is None:
            raise AgentToolError(f"Unknown agent: {agent_code}")
        statement = select(KnowledgeNode).where(
            KnowledgeNode.organization_id == user.organization_id
        )
        if agent.knowledge_scopes:
            statement = statement.where(KnowledgeNode.node_type.in_(agent.knowledge_scopes))
        if source_ids:
            statement = statement.where(KnowledgeNode.source_id.in_(source_ids[:100]))
        candidate_pool = list((await self.db.scalars(statement.limit(200))).all())
        sources = await self._most_relevant(question, candidate_pool)
        framed_question = AiQuestion(
            service=agent.service_literal,  # type: ignore[arg-type]
            question=f"[{agent.name}] {question}"[:4000],
        )
        answer: GroundedAnswer = await self.provider.answer(framed_question, sources)
        correlation_id = str(uuid4())
        await write_audit(
            self.db,
            user,
            "agent.answered",
            "agent_answer",
            correlation_id,
            metadata={"agent": agent.code, "confidence": answer.confidence},
        )
        return AgentAnswer(
            agent_code=agent.code,
            correlation_id=correlation_id,
            response=answer.response,
            facts=answer.facts,
            citations=answer.citations,
            confidence=answer.confidence,
            limitations=answer.limitations,
            reproducibility_key=answer.reproducibility_key,
            required_human_approval=answer.confidence < 0.5 or agent.code == "remediation_advisor",
        )

    async def _most_relevant(
        self, question: str, candidate_pool: list[KnowledgeNode], *, top_k: int = 20
    ) -> list[KnowledgeNode]:
        """Retrieval step (Phase 10.3.3): narrows a large candidate pool.

        ``top_k`` matches the deterministic provider's own citation cap
        (``DeterministicGroundedProvider`` re-sorts and keeps the first 20):
        narrowing to any larger number would let that provider's alphabetical
        re-sort silently override this ranking. Below ``top_k`` there is
        nothing to narrow. Above it, ranking by relevance to the question --
        instead of arbitrary database order -- is what actually determines
        which facts the answer is grounded in.
        """
        if len(candidate_pool) <= top_k:
            return candidate_pool
        by_id = {node.id: node for node in candidate_pool}
        candidates = [(node.id, f"{node.label} {node.facts}") for node in candidate_pool]
        ranked = await self.retrieval.rank(question, candidates, top_k=top_k)
        return [by_id[item.source_id] for item in ranked]
