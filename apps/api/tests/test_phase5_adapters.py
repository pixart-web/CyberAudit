import pytest

from cyberaudit.adapters import (
    AdapterExecutionContext,
    AdapterRegistry,
    AdapterRequest,
    NormalizedTarget,
)
from cyberaudit.models import Intensity, TargetType
from cyberaudit.network_security import NetworkPolicyViolation


async def progress(_: int, __: str) -> None:
    return None


async def not_cancelled() -> bool:
    return False


def request(
    adapter_code: str,
    configuration: dict[str, object],
    target_type: TargetType = TargetType.REPOSITORY,
) -> AdapterRequest:
    return AdapterRequest(
        adapter_code=adapter_code,
        target=NormalizedTarget(
            target_type=target_type,
            value="demo/repository" if target_type == TargetType.REPOSITORY else "http://127.0.0.1",
        ),
        technique="safe-review",
        intensity=Intensity.PASSIVE,
        configuration=configuration,
    )


def test_registry_only_loads_allowlisted_phase5_adapters() -> None:
    registry = AdapterRegistry()
    codes = {item.code for item in registry.metadata()}
    assert "cyberaudit.web_inventory" in codes
    assert "cyberaudit.api_contract_analysis" in codes
    assert "cyberaudit.secret_detection" in codes
    with pytest.raises(LookupError, match="Unknown adapter"):
        registry.get("user.supplied.plugin")


@pytest.mark.asyncio
async def test_phase5_adapter_rejects_extra_configuration_fields() -> None:
    adapter = AdapterRegistry().get("cyberaudit.secret_detection")
    result = await adapter.validate_configuration(
        {
            "filename": "fixture.env",
            "content": "DEMO=not-sensitive",
            "command": "curl example.invalid",
        }
    )
    assert result.valid is False
    assert result.errors


@pytest.mark.asyncio
async def test_secret_adapter_outputs_only_fingerprint_and_mask() -> None:
    adapter = AdapterRegistry().get("cyberaudit.secret_detection")
    raw = "demo_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    adapter_request = request(
        "cyberaudit.secret_detection",
        {"filename": "fixture.env", "content": f"VALUE={raw}"},
    )
    context = AdapterExecutionContext(
        execution_id="phase5-test",
        request=adapter_request,
        progress_callback=progress,
        cancellation_check=not_cancelled,
        allowed_destinations=[],
    )
    result = await adapter.execute(context)
    assert raw not in result.raw_output.decode()
    assert "fingerprint" in result.raw_output.decode()
    assert result.summary.simulated is False


@pytest.mark.asyncio
async def test_web_inventory_requires_central_network_policy() -> None:
    adapter = AdapterRegistry().get("cyberaudit.web_inventory")
    adapter_request = request(
        "cyberaudit.web_inventory",
        {},
        target_type=TargetType.URL,
    )
    context = AdapterExecutionContext(
        execution_id="phase5-web-test",
        request=adapter_request,
        progress_callback=progress,
        cancellation_check=not_cancelled,
        allowed_destinations=["127.0.0.1"],
    )
    with pytest.raises(NetworkPolicyViolation, match="network_policy_missing"):
        await adapter.execute(context)


@pytest.mark.asyncio
async def test_api_contract_adapter_does_not_need_network() -> None:
    adapter = AdapterRegistry().get("cyberaudit.api_contract_analysis")
    adapter_request = request(
        "cyberaudit.api_contract_analysis",
        {"declared_controls": {"authentication_documented": True}},
    )
    context = AdapterExecutionContext(
        execution_id="phase5-contract-test",
        request=adapter_request,
        progress_callback=progress,
        cancellation_check=not_cancelled,
        allowed_destinations=[],
    )
    result = await adapter.execute(context)
    assert result.summary.status == "success"
    assert result.raw_output
