"""Offline-first acceptance (Phase 10.3 section 4, extended in Phase 10.4.17).

A supported CyberAudit installation must perform its essential functionality
without Internet connectivity. These tests simulate "no network" by making
every outbound socket connection raise, then exercise the AI/agent surface
that would be the first thing to break if any core path secretly depended on
a reachable external service. This is a permanent regression test, extended
in each phase to cover its new local-first surfaces (Phase 10.4: engagement
reporting, the local model registry, and offline update-bundle validation).
"""

from __future__ import annotations

import socket
from datetime import datetime, timezone

import pytest

from cyberaudit.agent_runtime import AGENT_CATALOG, CyberAgentRuntime
from cyberaudit.ai_runtime import (
    HardwareCapabilityService,
    build_inference_backend,
)
from cyberaudit.ai_runtime_models import AiModelManifest
from cyberaudit.config import Settings
from cyberaudit.engagement_models import Report
from cyberaudit.engagement_services import ReportService
from cyberaudit.enterprise_models import KnowledgeNode
from cyberaudit.local_retrieval import LocalRetrievalService, build_embedding_backend
from cyberaudit.models import Engagement, EngagementMode, Organization, User
from cyberaudit.update_bundle import (
    TrustedKeyStore,
    UpdateBundleService,
    UpdateManifest,
    generate_signing_keypair,
    sign_manifest,
)


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


@pytest.mark.asyncio
async def test_engagement_report_generation_works_offline(db, no_network):
    """Section 52: "generate a report" must work with zero network access."""
    organization = Organization(name="Offline Report Tenant", slug="offline-report-tenant")
    db.add(organization)
    await db.flush()
    engagement = Engagement(
        organization_id=organization.id,
        client_id="client-offline",
        name="Offline Assessment",
        code="OFFLINE-001",
        mode=EngagementMode.CLIENT,
    )
    db.add(engagement)
    user = User(
        organization_id=organization.id,
        name="Offline Consultant",
        email="offline-consultant@example.invalid",
        password_hash="",  # noqa: S106 - authentication is not exercised here
    )
    db.add(user)
    await db.flush()

    report = await ReportService(db).generate(
        organization.id, engagement.id, user, include_ai_summary=True
    )
    assert isinstance(report, Report)
    assert report.status == "draft"


@pytest.mark.asyncio
async def test_model_registry_works_offline(db, no_network):
    """Section 52: local knowledge/model metadata must remain usable offline."""
    from cyberaudit.ai_runtime import ModelRegistryService

    organization = Organization(name="Offline Model Tenant", slug="offline-model-tenant")
    db.add(organization)
    await db.flush()
    user = User(
        organization_id=organization.id,
        name="Offline Admin",
        email="offline-admin@example.invalid",
        password_hash="",  # noqa: S106 - authentication is not exercised here
    )
    db.add(user)
    await db.flush()

    service = ModelRegistryService(db)
    manifest = await service.register(
        model_id="qwen2.5:7b",
        family="qwen",
        version="2.5",
        quantization="q4",
        size_gb=4.7,
        context_window=32_000,
        capabilities=["knowledge_query"],
        ram_required_mb=8192,
        vram_required_mb=0,
        cpu_compatible=True,
        gpu_compatible=False,
        license="apache-2.0",
        source="local",
        sha256=None,
        registered_by=user.id,
    )
    assert isinstance(manifest, AiModelManifest)
    listed = await service.list_models()
    assert manifest.id in {item.id for item in listed}


@pytest.mark.asyncio
async def test_diagnostic_bundle_generation_works_offline(db, no_network):
    """Phase 10.4.1 section 49: the diagnostic bundle is pure local

    introspection (hardware detection, DB counts, redaction) -- it must
    never depend on reaching anything outside the host.
    """
    from cyberaudit.diagnostics import build_diagnostic_bundle

    organization = Organization(name="Offline Diagnostics Tenant", slug="offline-diag-tenant")
    db.add(organization)
    await db.flush()
    user = User(
        organization_id=organization.id,
        name="Offline Diagnostics Admin",
        email="offline-diag-admin@example.invalid",
        password_hash="",  # noqa: S106 - authentication is not exercised here
    )
    db.add(user)
    await db.flush()

    bundle = await build_diagnostic_bundle(db, Settings(), user)
    assert bundle.organization_id == organization.id


def test_offline_update_bundle_validation_needs_no_network(no_network):
    """Section 52: signature/checksum verification is pure local cryptography

    -- an air-gapped install must be able to validate a .caup bundle with
    zero network access, exactly as this ADR-029 service already does.
    """
    private_key, public_pem = generate_signing_keypair()
    manifest = UpdateManifest(
        bundle_id="offline-knowledge-pack",
        bundle_type="knowledge_pack",
        version="2026.09.0",
        created_at=datetime.now(timezone.utc),
        min_compatible_app_version="0.1.0",
        checksums={},
    )
    signature = sign_manifest(manifest, private_key)
    service = UpdateBundleService(TrustedKeyStore([public_pem]), current_app_version="0.1.0")
    result = service.validate(manifest.model_dump_json().encode(), signature, {})
    assert result.accepted is True
