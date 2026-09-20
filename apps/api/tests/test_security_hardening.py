"""Phase 10.3.12: additional cross-tenant isolation and AI failure-mode tests.

Consolidates the checks explicitly called for by section 45 of the
implementation brief that were not already covered by the milestone tests
in this phase: report generation cross-tenant isolation, a corrupt/revoked
model being excluded by the capability router, and a local-model timeout
degrading gracefully instead of raising through to the caller.
"""

import httpx
import pytest

from cyberaudit.agent_runtime import AGENT_CATALOG
from cyberaudit.ai_runtime import (
    CapabilityRouter,
    DisabledInferenceBackend,
    HardwareCapabilityService,
    LocalFirstProvider,
)
from cyberaudit.ai_runtime_models import AiModelManifest
from cyberaudit.engagement_services import EngagementNotFoundError, ReportService
from cyberaudit.enterprise_models import KnowledgeNode
from cyberaudit.enterprise_services import AiQuestion
from cyberaudit.models import Engagement, EngagementMode, Organization, User


async def _tenant_with_engagement(db, suffix: str) -> tuple[Organization, Engagement, User]:
    organization = Organization(name=f"Tenant {suffix}", slug=f"tenant-{suffix}")
    db.add(organization)
    await db.flush()
    engagement = Engagement(
        organization_id=organization.id,
        client_id=f"client-{suffix}",
        name=f"Assessment {suffix}",
        code=f"ENG-{suffix}",
        mode=EngagementMode.CLIENT,
    )
    db.add(engagement)
    user = User(
        organization_id=organization.id,
        name="Consultant",
        email=f"consultant-{suffix}@example.invalid",
        password_hash="",  # noqa: S106 - authentication is not exercised here
    )
    db.add(user)
    await db.flush()
    return organization, engagement, user


@pytest.mark.asyncio
async def test_report_generation_cannot_be_triggered_across_tenants(db):
    """Section 40: cross-tenant leakage is release-blocking.

    Even a caller who somehow knows another tenant's engagement_id must
    not be able to generate a report for it by asserting their own,
    different organization_id.
    """
    _, engagement_a, _ = await _tenant_with_engagement(db, "report-iso-a")
    organization_b, _, user_b = await _tenant_with_engagement(db, "report-iso-b")

    with pytest.raises(EngagementNotFoundError):
        await ReportService(db).generate(organization_b.id, engagement_a.id, user_b)


def _manifest(**overrides) -> AiModelManifest:
    base = dict(
        model_id="qwen2.5:7b",
        family="qwen",
        version="2.5",
        quantization="q4",
        size_gb=4.7,
        context_window=32_000,
        capabilities=["knowledge_query"],
        ram_required_mb=4096,
        vram_required_mb=0,
        cpu_compatible=True,
        gpu_compatible=False,
        install_status="installed",
        trust_status="verified",
    )
    base.update(overrides)
    return AiModelManifest(**base)


def test_capability_router_excludes_a_corrupt_model():
    hardware = HardwareCapabilityService.detect()
    corrupt = _manifest(install_status="corrupt")
    router = CapabilityRouter([corrupt], hardware)
    assert router.resolve("knowledge_query") is None


def test_capability_router_excludes_a_model_still_downloading():
    hardware = HardwareCapabilityService.detect()
    downloading = _manifest(install_status="downloading")
    router = CapabilityRouter([downloading], hardware)
    assert router.resolve("knowledge_query") is None


@pytest.mark.asyncio
async def test_local_model_timeout_degrades_to_the_deterministic_answer(db):
    """A local model that times out mid-generation must not fail the

    request end-to-end; LocalFirstProvider must fall back to the
    deterministic, evidence-grounded answer, same as an unreachable
    backend.
    """
    from cyberaudit.ai_runtime import OllamaInferenceBackend

    organization = Organization(name="Timeout Tenant", slug="timeout-tenant")
    db.add(organization)
    await db.flush()
    node = KnowledgeNode(
        organization_id=organization.id,
        node_type="finding",
        source_id="timeout-1",
        label="Slow to summarize",
        facts={"severity": "low"},
    )
    db.add(node)
    await db.flush()

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/tags":
            return httpx.Response(200, json={"models": []})
        raise httpx.TimeoutException("model generation timed out", request=request)

    backend = OllamaInferenceBackend(
        "http://127.0.0.1:11434", 5.0, transport=httpx.MockTransport(handler)
    )
    hardware = HardwareCapabilityService.detect()
    router = CapabilityRouter([_manifest()], hardware)
    provider = LocalFirstProvider(router, backend)
    question = AiQuestion(service="explanation", question="Summarize the finding")

    answer = await provider.answer(question, [node])
    assert answer.facts  # deterministic facts are still present
    assert any("Local model call failed" in item for item in answer.limitations)


@pytest.mark.asyncio
async def test_agent_context_never_crosses_tenants_even_with_matching_source_ids(db):
    """Two tenants each have a KnowledgeNode with the same source_id; asking

    an agent as tenant A must never surface tenant B's row, even when an
    attacker-supplied source_ids filter happens to match both.
    """
    from cyberaudit.agent_runtime import CyberAgentRuntime

    organization_a = Organization(name="Ctx Tenant A", slug="ctx-tenant-a")
    organization_b = Organization(name="Ctx Tenant B", slug="ctx-tenant-b")
    db.add_all([organization_a, organization_b])
    await db.flush()
    db.add_all(
        [
            KnowledgeNode(
                organization_id=organization_a.id,
                node_type="finding",
                source_id="shared-id",
                label="Tenant A's own finding",
                facts={},
            ),
            KnowledgeNode(
                organization_id=organization_b.id,
                node_type="finding",
                source_id="shared-id",
                label="Tenant B's secret finding",
                facts={},
            ),
        ]
    )
    user_a = User(
        organization_id=organization_a.id,
        name="Analyst A",
        email="analyst-ctx-a@example.invalid",
        password_hash="",  # noqa: S106 - authentication is not exercised here
    )
    db.add(user_a)
    await db.flush()

    answer = await CyberAgentRuntime(db).ask(
        "security_analyst", user_a, "Explain this finding", source_ids=["shared-id"]
    )
    labels = [fact["label"] for fact in answer.facts]
    assert labels == ["Tenant A's own finding"]
    assert "Tenant B's secret finding" not in labels


def test_agent_catalog_has_no_agent_with_direct_infrastructure_tools():
    """Section 18: never give an LLM/agent direct DB, Docker socket or shell

    access. Every allowed_tools entry must resolve to a registered,
    read-only AgentTool -- there is no way to name an ad-hoc tool.
    """
    from cyberaudit.agent_runtime import AGENT_TOOLS

    dangerous_names = {"shell", "docker", "sql", "exec", "eval"}
    for agent in AGENT_CATALOG.values():
        for tool_name in agent.allowed_tools:
            assert tool_name in AGENT_TOOLS
            assert tool_name not in dangerous_names


@pytest.mark.asyncio
async def test_disabled_inference_backend_never_silently_succeeds():
    backend = DisabledInferenceBackend()
    health = await backend.health_check()
    assert health.healthy is False
    with pytest.raises(Exception):  # noqa: B017 - any failure is acceptable, silent success is not
        await backend.generate("any-model", "prompt")
