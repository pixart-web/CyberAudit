import pytest

from cyberaudit.adapters import AdapterRegistry, NormalizedTarget
from cyberaudit.models import TargetType


@pytest.mark.asyncio
async def test_phase4_adapters_are_static_and_healthy():
    registry = AdapterRegistry()
    expected = {
        "cyberaudit.host_discovery",
        "cyberaudit.port_discovery",
        "cyberaudit.service_identification",
        "cyberaudit.os_identification",
        "cyberaudit.exposure_assessment",
        "cyberaudit.vulnerability_correlation",
    }
    assert expected.issubset({item.code for item in registry.metadata()})
    for code in expected:
        assert (await registry.health_check(code)).healthy


@pytest.mark.asyncio
async def test_discovery_configuration_rejects_extra_fields_and_large_limits():
    adapter = AdapterRegistry().get("cyberaudit.host_discovery")
    assert not (
        await adapter.validate_configuration(
            {"probe_profile": "minimal", "maximum_hosts": 8, "command": "nmap"}
        )
    ).valid
    assert not (
        await adapter.validate_configuration({"probe_profile": "minimal", "maximum_hosts": 10_000})
    ).valid


@pytest.mark.asyncio
async def test_host_discovery_rejects_non_network_target():
    adapter = AdapterRegistry().get("cyberaudit.host_discovery")
    result = await adapter.validate_target(
        NormalizedTarget(target_type=TargetType.DOMAIN, value="example.invalid")
    )
    assert not result.valid
