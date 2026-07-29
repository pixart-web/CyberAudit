import asyncio

import pytest

from cyberaudit.discovery import (
    BoundedNetworkDiscovery,
    CalculatedDiscoveryPolicy,
    bounded_hosts,
    calculate_discovery_policy,
)
from cyberaudit.network_security import NetworkPolicyViolation


def test_policy_operator_can_only_reduce_limits():
    stored = CalculatedDiscoveryPolicy(maximum_hosts=32, maximum_ports=16)
    calculated = calculate_discovery_policy(stored, requested_hosts=100, requested_ports=2)
    assert calculated.maximum_hosts == 32
    assert calculated.maximum_ports == 2


def test_bounded_hosts_rejects_scope_expansion():
    with pytest.raises(NetworkPolicyViolation, match="cidr_host_limit_exceeded"):
        bounded_hosts("10.0.0.0/16", CalculatedDiscoveryPolicy(maximum_hosts=8))


def test_bounded_hosts_supports_ipv4_ipv6_and_exclusions():
    ipv4 = bounded_hosts(
        "10.0.0.0/30",
        CalculatedDiscoveryPolicy(maximum_hosts=4, excluded_targets=["10.0.0.2/32"]),
    )
    ipv6 = bounded_hosts("fd00::/126", CalculatedDiscoveryPolicy(maximum_hosts=4))
    assert ipv4 == ["10.0.0.1"]
    assert len(ipv6) == 3


@pytest.mark.asyncio
async def test_tcp_connect_observes_only_allowlisted_port():
    server = await asyncio.start_server(lambda _r, w: w.close(), "127.0.0.1", 0)
    port = int(server.sockets[0].getsockname()[1])
    policy = CalculatedDiscoveryPolicy(
        maximum_hosts=1,
        maximum_ports=1,
        permitted_ports=[port],
        host_timeout=1,
        total_timeout=3,
        packets_per_second=100,
    )
    discovery = BoundedNetworkDiscovery(policy)

    async def cancelled() -> bool:
        return False

    async def progress(_value: int, _message: str) -> None:
        return None

    try:
        results = await discovery.scan(["127.0.0.1"], [port], cancelled, progress)
        assert results[0]["state"] == "open"
        with pytest.raises(NetworkPolicyViolation, match="port_not_permitted"):
            await discovery.scan(["127.0.0.1"], [port + 1], cancelled, progress)
    finally:
        server.close()
        await server.wait_closed()
