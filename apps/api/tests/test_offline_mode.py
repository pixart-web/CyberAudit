"""Offline-first acceptance (Phase 10.3, section 4 of the implementation brief).

A supported CyberAudit installation must perform its essential functionality
without Internet connectivity. These tests simulate "no network" by making
every outbound socket connection raise, then exercise the AI/agent surface
that would be the first thing to break if any core path secretly depended on
a reachable external service.
"""

from __future__ import annotations

import socket

import pytest

from cyberaudit.agent_runtime import AGENT_CATALOG, CyberAgentRuntime
from cyberaudit.ai_runtime import (
    HardwareCapabilityService,
    build_inference_backend,
)
from cyberaudit.config import Settings
from cyberaudit.enterprise_models import KnowledgeNode
from cyberaudit.local_retrieval import LocalRetrievalService, build_embedding_backend
from cyberaudit.models import Organization, User


@pytest.fixture
def no_network(monkeypatch):
    """Make every outbound socket connection fail, as if offline."""

    def _blocked(*args, **kwargs):
        raise OSError("network is unreachable (simulated offline mode)")

    monkeypatch.setattr(socket.socket, "connect", _blocked)
    yield


def test_hardware_detection_needs_no_network(no_network):
    capabilities = HardwareCapabilityService.detect()
    assert capabilities.cpu_cores >= 1
    profile = HardwareCapabilityService.classify(capabilities)
    assert profile is not None


@pytest.mark.asyncio
async def test_default_inference_backend_is_offline_safe(no_network):
    settings = Settings(ai_runtime_backend="disabled")
    backend = build_inference_backend(settings)
    health = await backend.health_check()
    assert health.healthy is False  # explicit, not a crash


@pytest.mark.asyncio
async def test_default_embedding_backend_is_offline_safe(no_network):
    settings = Settings(ai_runtime_backend="disabled")
    backend = build_embedding_backend(settings)
    health = await backend.health_check()
    assert health.healthy is False


@pytest.mark.asyncio
async def test_configured_ollama_backend_degrades_instead_of_crashing(no_network):
    """An administrator who enabled a local backend on a now-offline host

    must see a clear "unavailable" health status, not an unhandled network
    exception bubbling out of the AI runtime.
    """
    settings = Settings(ai_runtime_backend="ollama", ai_runtime_base_url="http://127.0.0.1:11434")
    backend = build_inference_backend(settings)
    health = await backend.health_check()
    assert health.healthy is False


@pytest.mark.asyncio
async def test_every_agent_answers_offline_with_no_installed_model(db, no_network):
    """The full agent surface -- all ten catalog entries -- must work with

    zero local models installed and zero network access, using only the
    deterministic, evidence-grounded provider.
    """
    organization = Organization(name="Offline Tenant", slug="offline-tenant")
    db.add(organization)
    await db.flush()
    db.add(
        KnowledgeNode(
            organization_id=organization.id,
            node_type="finding",
            source_id="offline-1",
            label="Recorded during a previous, connected assessment",
            facts={"severity": "medium"},
        )
    )
    user = User(
        organization_id=organization.id,
        name="Offline Analyst",
        email="offline-analyst@example.invalid",
        password_hash="",  # noqa: S106 - authentication is not exercised here
    )
    db.add(user)
    await db.flush()

    runtime = CyberAgentRuntime(db)
    for agent_code in AGENT_CATALOG:
        answer = await runtime.ask(agent_code, user, "Summarize what is known")
        assert answer.agent_code == agent_code
        assert isinstance(answer.response, str) and answer.response


@pytest.mark.asyncio
async def test_retrieval_narrows_a_large_pool_offline(no_network):
    service = LocalRetrievalService(
        build_embedding_backend(Settings(ai_runtime_backend="disabled"))
    )
    candidates = [(f"id-{i}", f"finding number {i}") for i in range(50)]
    ranked = await service.rank("finding number 7", candidates, top_k=5)
    assert len(ranked) == 5
    assert ranked[0].method == "lexical"
