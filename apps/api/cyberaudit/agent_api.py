"""REST API for the CyberAgentRuntime and AgentToolGateway (Phase 10.3.5)."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.ext.asyncio import AsyncSession

from cyberaudit.agent_runtime import (
    AGENT_CATALOG,
    AgentToolError,
    AgentToolGateway,
    CyberAgentRuntime,
)
from cyberaudit.db import get_db
from cyberaudit.models import User
from cyberaudit.security import require_permission

router = APIRouter(prefix="/api/v1/agents", tags=["cyber-agents"])


@router.get("")
async def list_agents(user: User = Depends(require_permission("ai_assistant.read"))):
    return {
        "items": [
            {
                "code": agent.code,
                "name": agent.name,
                "mission": agent.mission,
                "knowledge_scopes": list(agent.knowledge_scopes),
                "allowed_tools": list(agent.allowed_tools),
            }
            for agent in AGENT_CATALOG.values()
        ]
    }


class AgentAskRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    question: str = Field(min_length=3, max_length=4000)
    source_ids: list[str] = Field(default_factory=list, max_length=100)


@router.post("/{agent_code}/ask", status_code=201)
async def ask_agent(
    agent_code: str,
    payload: AgentAskRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("ai_assistant.use")),
):
    if agent_code not in AGENT_CATALOG:
        raise HTTPException(404, f"Unknown agent: {agent_code}")
    answer = await CyberAgentRuntime(db).ask(
        agent_code, user, payload.question, source_ids=payload.source_ids or None
    )
    await db.commit()
    return asdict(answer)


@router.post("/{agent_code}/tools/{tool_name}")
async def invoke_agent_tool(
    agent_code: str,
    tool_name: str,
    payload: dict[str, Any],
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("ai_assistant.use")),
):
    agent = AGENT_CATALOG.get(agent_code)
    if agent is None:
        raise HTTPException(404, f"Unknown agent: {agent_code}")
    try:
        result = await AgentToolGateway(db).invoke(agent, tool_name, user, payload)
    except AgentToolError as exc:
        await db.rollback()
        raise HTTPException(422, str(exc)) from exc
    await db.commit()
    return result
