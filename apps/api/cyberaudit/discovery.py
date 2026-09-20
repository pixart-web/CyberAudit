"""Bounded, non-stealth network discovery primitives.

Only TCP connect is implemented.  There is no raw packet support, spoofing,
fragmentation, UDP, decoys, authentication or application command execution.
"""

from __future__ import annotations

import asyncio
import ipaddress
import time
from collections.abc import Awaitable, Callable
from typing import Any

from pydantic import BaseModel, Field

from cyberaudit.network_security import NetworkPolicyViolation

PORT_PROFILES: dict[str, tuple[int, ...]] = {
    "minimal": (22, 80, 443),
    "standard": (21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3389, 5432, 8080, 8443),
    "extended": (
        21,
        22,
        25,
        53,
        80,
        110,
        143,
        389,
        443,
        445,
        465,
        587,
        636,
        993,
        995,
        1433,
        1521,
        2049,
        2375,
        3306,
        3389,
        5432,
        6379,
        8080,
        8443,
        9200,
    ),
}


class CalculatedDiscoveryPolicy(BaseModel):
    maximum_hosts: int = Field(default=64, ge=1, le=1024)
    maximum_ports: int = Field(default=32, ge=1, le=128)
    packets_per_second: int = Field(default=20, ge=1, le=100)
    concurrent_hosts: int = Field(default=8, ge=1, le=32)
    concurrent_ports: int = Field(default=8, ge=1, le=32)
    host_timeout: float = Field(default=2.0, ge=0.1, le=10)
    total_timeout: float = Field(default=120, ge=1, le=900)
    permitted_ports: list[int] = Field(default_factory=lambda: list(PORT_PROFILES["standard"]))
    forbidden_ports: list[int] = Field(default_factory=list)
    allow_tcp_discovery: bool = True
    allow_service_detection: bool = True
    excluded_targets: list[str] = Field(default_factory=list)


def calculate_discovery_policy(
    stored: CalculatedDiscoveryPolicy,
    requested_hosts: int | None = None,
    requested_ports: int | None = None,
) -> CalculatedDiscoveryPolicy:
    """The operator may only reduce limits, never increase them."""

    return stored.model_copy(
        update={
            "maximum_hosts": min(stored.maximum_hosts, requested_hosts or stored.maximum_hosts),
            "maximum_ports": min(stored.maximum_ports, requested_ports or stored.maximum_ports),
        }
    )


def bounded_hosts(target: str, policy: CalculatedDiscoveryPolicy) -> list[str]:
    network = ipaddress.ip_network(target, strict=False)
    if network.num_addresses > policy.maximum_hosts + 2:
        raise NetworkPolicyViolation("cidr_host_limit_exceeded")
    excluded = [ipaddress.ip_network(value, strict=False) for value in policy.excluded_targets]
    hosts = [
        str(address)
        for address in network.hosts()
        if not any(address in excluded_network for excluded_network in excluded)
    ]
    if len(hosts) > policy.maximum_hosts:
        raise NetworkPolicyViolation("cidr_host_limit_exceeded")
    return hosts


class BoundedNetworkDiscovery:
    def __init__(self, policy: CalculatedDiscoveryPolicy):
        self.policy = policy
        self._last_request = 0.0
        self._rate_lock = asyncio.Lock()

    async def _rate_limit(self) -> None:
        async with self._rate_lock:
            interval = 1 / self.policy.packets_per_second
            delay = interval - (time.monotonic() - self._last_request)
            if delay > 0:
                await asyncio.sleep(delay)
            self._last_request = time.monotonic()

    async def tcp_connect(self, host: str, port: int) -> dict[str, Any]:
        if not self.policy.allow_tcp_discovery:
            raise NetworkPolicyViolation("tcp_discovery_disabled")
        if port not in self.policy.permitted_ports or port in self.policy.forbidden_ports:
            raise NetworkPolicyViolation("port_not_permitted")
        await self._rate_limit()
        started = time.monotonic()
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=self.policy.host_timeout
            )
            writer.close()
            await writer.wait_closed()
            return {
                "host": host,
                "port": port,
                "state": "open",
                "latency_ms": round((time.monotonic() - started) * 1000, 2),
                "method": "tcp_connect",
                "confidence": 0.95,
            }
        except TimeoutError:
            return {
                "host": host,
                "port": port,
                "state": "filtered",
                "latency_ms": None,
                "method": "tcp_connect",
                "confidence": 0.65,
            }
        except OSError:
            return {
                "host": host,
                "port": port,
                "state": "closed",
                "latency_ms": round((time.monotonic() - started) * 1000, 2),
                "method": "tcp_connect",
                "confidence": 0.9,
            }

    async def scan(
        self,
        hosts: list[str],
        ports: list[int],
        cancelled: Callable[[], Awaitable[bool]],
        progress: Callable[[int, str], Awaitable[None]],
    ) -> list[dict[str, Any]]:
        if len(hosts) > self.policy.maximum_hosts:
            raise NetworkPolicyViolation("host_limit_exceeded")
        unique_ports = sorted(set(ports))
        if len(unique_ports) > self.policy.maximum_ports:
            raise NetworkPolicyViolation("port_limit_exceeded")
        if any(
            port not in self.policy.permitted_ports or port in self.policy.forbidden_ports
            for port in unique_ports
        ):
            raise NetworkPolicyViolation("port_not_permitted")
        pairs = [(host, port) for host in hosts for port in unique_ports]
        semaphore = asyncio.Semaphore(
            min(self.policy.concurrent_hosts * self.policy.concurrent_ports, 32)
        )
        results: list[dict[str, Any]] = []

        async def one(host: str, port: int) -> None:
            async with semaphore:
                if await cancelled():
                    raise asyncio.CancelledError
                results.append(await self.tcp_connect(host, port))
                completed = len(results)
                await progress(
                    20 + int((completed / max(1, len(pairs))) * 60),
                    f"Observação controlada {completed}/{len(pairs)}",
                )

        await asyncio.wait_for(
            asyncio.gather(*(one(host, port) for host, port in pairs)),
            timeout=self.policy.total_timeout,
        )
        return results
