import json

import pytest

from cyberaudit.adapters import (
    AdapterRegistry,
    DemoAssessmentAdapter,
    NormalizedFinding,
    NormalizedTarget,
    finding_fingerprint,
    sanitize_raw_output,
)
from cyberaudit.models import Criticality, TargetType


@pytest.mark.asyncio
async def test_demo_configuration_rejects_extra_fields():
    result = await DemoAssessmentAdapter().validate_configuration(
        {"scenario": "clean", "duration_seconds": 10, "finding_count": 0, "command": "no"}
    )
    assert result.valid is False


@pytest.mark.asyncio
async def test_demo_configuration_rejects_invalid_scenario():
    result = await DemoAssessmentAdapter().validate_configuration(
        {"scenario": "unknown", "duration_seconds": 10, "finding_count": 0}
    )
    assert result.valid is False


@pytest.mark.asyncio
async def test_demo_target_validation():
    adapter = DemoAssessmentAdapter()
    assert (
        await adapter.validate_target(NormalizedTarget(target_type=TargetType.IP, value="10.0.0.1"))
    ).valid


@pytest.mark.asyncio
async def test_health_check_is_safe_and_online():
    result = await AdapterRegistry().health_check("cyberaudit.demo_assessment")
    assert result.healthy
    assert "rede" in result.message


def test_unknown_adapter_is_blocked():
    with pytest.raises(LookupError):
        AdapterRegistry().get("user.supplied.module")


def test_duplicate_adapter_is_blocked():
    with pytest.raises(ValueError):
        AdapterRegistry([DemoAssessmentAdapter(), DemoAssessmentAdapter()])


def test_raw_output_sanitization():
    raw = json.dumps({"password": "secret-value", "token": "abc", "safe": "ok"}).encode()
    sanitized, flag = sanitize_raw_output(raw)
    assert flag
    assert b"secret-value" not in sanitized
    assert b"abc" not in sanitized
    assert sanitized.count(b"[REDACTED]") == 2


def test_raw_output_limit():
    with pytest.raises(ValueError, match="exceeds"):
        sanitize_raw_output(b"x" * 100, limit=10)


def test_fingerprint_is_stable_and_uses_logical_fields():
    finding = NormalizedFinding(
        title="[SIMULADO] Exemplo",
        description="Simulado",
        category="configuration",
        severity=Criticality.MEDIUM,
        confidence="high",
        affected_component="service-a",
        technical_impact="Simulado",
        business_impact="Simulado",
        remediation="Simulado",
        validation_steps=[],
        evidence=[],
        source_identifier="demo.rule",
        logical_location="/settings",
    )
    first = finding_fingerprint("org", "eng", None, finding, "cyberaudit.demo_assessment")
    second = finding_fingerprint("org", "eng", None, finding, "cyberaudit.demo_assessment")
    assert first == second
    changed = finding.model_copy(update={"logical_location": "/other"})
    assert first != finding_fingerprint("org", "eng", None, changed, "cyberaudit.demo_assessment")


@pytest.mark.asyncio
async def test_parse_output_marks_every_finding_simulated():
    adapter = DemoAssessmentAdapter()
    output = await adapter.parse_output(
        json.dumps(
            {
                "simulated": True,
                "scenario": "mixed",
                "finding_count": 2,
                "target": "10.0.0.1",
                "summary": {"status": "success", "message": "ok", "simulated": True},
            }
        ).encode()
    )
    assert len(output.findings) == 2
    assert all(item.simulated and item.title.startswith("[SIMULADO]") for item in output.findings)
