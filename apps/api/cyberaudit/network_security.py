"""Network safety primitives used by every network-capable adapter.

The module deliberately owns DNS resolution and socket creation. Adapters receive
validated, bounded responses and never instantiate an HTTP client directly.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Literal
from urllib.parse import SplitResult, urljoin, urlsplit

import dns.asyncresolver
import dns.exception
import dns.resolver
from pydantic import BaseModel, ConfigDict, Field, field_validator

from cyberaudit.observability import adapter_bytes, adapter_requests, dns_queries


class NetworkPolicyViolation(ValueError):
    """A requested network action violates the backend-computed policy."""


class DnsRebindingBlocked(NetworkPolicyViolation):
    """A hostname changed resolution during one execution."""


class NetworkExecutionPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    maximum_requests: int = Field(default=8, ge=1, le=64)
    maximum_requests_per_second: float = Field(default=2.0, gt=0, le=10)
    maximum_response_bytes: int = Field(default=262_144, ge=1024, le=2_097_152)
    maximum_redirects: int = Field(default=2, ge=0, le=5)
    connect_timeout: float = Field(default=3.0, gt=0, le=15)
    read_timeout: float = Field(default=5.0, gt=0, le=30)
    total_timeout: float = Field(default=15.0, gt=0, le=120)
    allowed_schemes: tuple[Literal["http", "https"], ...] = ("https", "http")
    allowed_ports: tuple[int, ...] = (80, 443)
    allow_private_addresses: bool = False
    allow_public_addresses: bool = True
    resolve_once: bool = True
    deny_scope_expansion: bool = True
    user_agent: str = "CyberAudit/0.3 (+authorized-security-assessment)"

    @field_validator("allowed_ports")
    @classmethod
    def validate_ports(cls, value: tuple[int, ...]) -> tuple[int, ...]:
        if not value or any(port < 1 or port > 65535 for port in value):
            raise ValueError("allowed_ports contains an invalid port")
        return value


class ResolvedDestination(BaseModel):
    hostname: str
    addresses: list[str]
    query_count: int
    cached: bool = False


class DnsRecordSet(BaseModel):
    hostname: str
    record_type: str
    values: list[str]
    ttl: int | None = None
    query_count: int
    cached: bool = False


class SecureHttpResponse(BaseModel):
    requested_url: str
    final_url: str
    status_code: int
    reason: str
    headers: dict[str, list[str]]
    body: bytes
    peer_ip: str
    redirects: list[str] = Field(default_factory=list)
    request_count: int
    bytes_received: int
    duration_ms: int


Lookup = Callable[[str, int], Awaitable[list[str]]]
CancellationCheck = Callable[[], Awaitable[bool]]


async def _system_lookup(hostname: str, port: int) -> list[str]:
    loop = asyncio.get_running_loop()
    records = await loop.getaddrinfo(
        hostname,
        port,
        family=socket.AF_UNSPEC,
        type=socket.SOCK_STREAM,
        proto=socket.IPPROTO_TCP,
    )
    return sorted({str(item[4][0]) for item in records})


def normalize_hostname(value: str) -> str:
    hostname = value.rstrip(".").strip().lower()
    if not hostname or len(hostname) > 253:
        raise NetworkPolicyViolation("invalid_hostname")
    try:
        ascii_name = hostname.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise NetworkPolicyViolation("invalid_hostname") from exc
    labels = ascii_name.split(".")
    if any(
        not label
        or len(label) > 63
        or label.startswith("-")
        or label.endswith("-")
        or not all(character.isalnum() or character == "-" for character in label)
        for label in labels
    ):
        raise NetworkPolicyViolation("invalid_hostname")
    return ascii_name


_CLOUD_METADATA_IPS = {
    ipaddress.ip_address("169.254.169.254"),
    ipaddress.ip_address("169.254.170.2"),
    ipaddress.ip_address("100.100.100.200"),
    ipaddress.ip_address("192.0.0.192"),
    ipaddress.ip_address("fd00:ec2::254"),
}


def validate_ip_address(address: str, policy: NetworkExecutionPolicy) -> ipaddress._BaseAddress:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError as exc:
        raise NetworkPolicyViolation("invalid_ip_address") from exc
    if ip in _CLOUD_METADATA_IPS:
        raise NetworkPolicyViolation("cloud_metadata_address_blocked")
    if ip.is_unspecified:
        raise NetworkPolicyViolation("unspecified_address_blocked")
    if ip.is_multicast:
        raise NetworkPolicyViolation("multicast_address_blocked")
    if ip.is_link_local:
        raise NetworkPolicyViolation("link_local_address_blocked")
    if ip.is_loopback and not policy.allow_private_addresses:
        raise NetworkPolicyViolation("loopback_address_blocked")
    if ip.is_reserved and not (ip.is_private and policy.allow_private_addresses):
        raise NetworkPolicyViolation("reserved_address_blocked")
    if ip.is_private and not policy.allow_private_addresses:
        raise NetworkPolicyViolation("private_address_blocked")
    if not ip.is_private and not policy.allow_public_addresses:
        raise NetworkPolicyViolation("public_address_blocked")
    return ip


def destination_matches_scope(hostname: str, address: str, allowed: list[str]) -> bool:
    normalized = normalize_hostname(hostname)
    ip = ipaddress.ip_address(address)
    for raw in allowed:
        value = raw.strip()
        try:
            if "/" in value and ip in ipaddress.ip_network(value, strict=False):
                return True
            if ip == ipaddress.ip_address(value):
                return True
        except ValueError:
            pass
        parsed = urlsplit(value if "://" in value else f"//{value}")
        candidate = parsed.hostname or value
        try:
            if normalize_hostname(candidate) == normalized:
                return True
        except NetworkPolicyViolation:
            continue
    return False


class SecureDnsResolver:
    def __init__(
        self,
        policy: NetworkExecutionPolicy,
        allowed_destinations: list[str],
        lookup: Lookup | None = None,
    ) -> None:
        self.policy = policy
        self.allowed_destinations = allowed_destinations
        self._lookup = lookup or _system_lookup
        self._cache: dict[tuple[str, int], tuple[str, ...]] = {}
        self._record_cache: dict[tuple[str, str], DnsRecordSet] = {}
        self.query_count = 0

    async def resolve(
        self, hostname: str, port: int, *, revalidate: bool = False
    ) -> ResolvedDestination:
        normalized = normalize_hostname(hostname)
        key = (normalized, port)
        if key in self._cache and not revalidate:
            return ResolvedDestination(
                hostname=normalized,
                addresses=list(self._cache[key]),
                query_count=self.query_count,
                cached=True,
            )
        if self.query_count >= self.policy.maximum_requests:
            raise NetworkPolicyViolation("dns_query_limit_exceeded")
        self.query_count += 1
        dns_queries.labels(record_type="ADDRESS").inc()
        try:
            addresses = await asyncio.wait_for(
                self._lookup(normalized, port), timeout=self.policy.connect_timeout
            )
        except TimeoutError as exc:
            raise NetworkPolicyViolation("dns_resolution_timeout") from exc
        if not addresses:
            raise NetworkPolicyViolation("dns_no_addresses")
        validated = tuple(
            sorted({str(validate_ip_address(address, self.policy)) for address in addresses})
        )
        previous = self._cache.get(key)
        if previous is not None and previous != validated:
            raise DnsRebindingBlocked("dns_rebinding_blocked")
        if self.policy.deny_scope_expansion and not all(
            destination_matches_scope(normalized, address, self.allowed_destinations)
            for address in validated
        ):
            raise NetworkPolicyViolation("resolved_address_out_of_scope")
        self._cache[key] = validated
        return ResolvedDestination(
            hostname=normalized,
            addresses=list(validated),
            query_count=self.query_count,
        )

    async def query_records(self, hostname: str, record_type: str) -> DnsRecordSet:
        normalized = normalize_hostname(hostname)
        kind = record_type.upper()
        if kind not in {"A", "AAAA", "CNAME", "MX", "NS", "TXT", "CAA", "SOA", "DNSKEY"}:
            raise NetworkPolicyViolation("dns_record_type_blocked")
        key = (normalized, kind)
        cached = self._record_cache.get(key)
        if cached:
            return cached.model_copy(update={"cached": True})
        if self.query_count >= self.policy.maximum_requests:
            raise NetworkPolicyViolation("dns_query_limit_exceeded")
        self.query_count += 1
        dns_queries.labels(record_type=kind).inc()
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = self.policy.total_timeout
        resolver.timeout = self.policy.connect_timeout
        try:
            answer = await resolver.resolve(
                normalized,
                kind,
                lifetime=self.policy.total_timeout,
                search=False,
                raise_on_no_answer=False,
            )
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            values: list[str] = []
            ttl = None
        except (dns.exception.Timeout, dns.resolver.NoNameservers) as exc:
            raise NetworkPolicyViolation("dns_resolution_failed") from exc
        else:
            values = [item.to_text().strip() for item in answer]
            ttl = answer.rrset.ttl if answer.rrset else None
        if kind in {"A", "AAAA"}:
            for value in values:
                validate_ip_address(value, self.policy)
                if self.policy.deny_scope_expansion and not destination_matches_scope(
                    normalized, value, self.allowed_destinations
                ):
                    raise NetworkPolicyViolation("resolved_address_out_of_scope")
        result = DnsRecordSet(
            hostname=normalized,
            record_type=kind,
            values=values,
            ttl=ttl,
            query_count=self.query_count,
        )
        self._record_cache[key] = result
        return result


@dataclass(frozen=True)
class _ValidatedUrl:
    parsed: SplitResult
    port: int


def validate_url(url: str, policy: NetworkExecutionPolicy) -> _ValidatedUrl:
    parsed = urlsplit(url)
    if parsed.scheme not in policy.allowed_schemes:
        raise NetworkPolicyViolation("url_scheme_blocked")
    if parsed.username is not None or parsed.password is not None:
        raise NetworkPolicyViolation("url_credentials_blocked")
    if not parsed.hostname:
        raise NetworkPolicyViolation("url_hostname_missing")
    normalize_hostname(parsed.hostname)
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as exc:
        raise NetworkPolicyViolation("url_port_invalid") from exc
    if port not in policy.allowed_ports:
        raise NetworkPolicyViolation("url_port_blocked")
    if parsed.fragment:
        raise NetworkPolicyViolation("url_fragment_not_allowed")
    return _ValidatedUrl(parsed=parsed, port=port)


class SecureHttpClient:
    def __init__(
        self,
        policy: NetworkExecutionPolicy,
        allowed_destinations: list[str],
        resolver: SecureDnsResolver | None = None,
    ) -> None:
        self.policy = policy
        self.allowed_destinations = allowed_destinations
        self.resolver = resolver or SecureDnsResolver(policy, allowed_destinations)
        self._requests = 0
        self._last_request_at = 0.0

    async def request(
        self,
        url: str,
        *,
        method: Literal["HEAD", "GET"] = "HEAD",
        cancellation_check: CancellationCheck | None = None,
    ) -> SecureHttpResponse:
        started = time.monotonic()
        current = url
        redirects: list[str] = []
        while True:
            if cancellation_check and await cancellation_check():
                raise asyncio.CancelledError
            remaining = self.policy.total_timeout - (time.monotonic() - started)
            if remaining <= 0:
                raise NetworkPolicyViolation("total_timeout_exceeded")
            response = await self._await_request(
                current,
                method,
                remaining,
                cancellation_check,
            )
            location = first_header(response.headers, "location")
            if response.status_code not in {301, 302, 303, 307, 308} or not location:
                response.redirects = redirects
                response.request_count = self._requests
                response.duration_ms = int((time.monotonic() - started) * 1000)
                return response
            if len(redirects) >= self.policy.maximum_redirects:
                raise NetworkPolicyViolation("redirect_limit_exceeded")
            next_url = urljoin(current, location)
            validated = validate_url(next_url, self.policy)
            await self.resolver.resolve(
                validated.parsed.hostname or "", validated.port, revalidate=True
            )
            if next_url in redirects or next_url == current:
                raise NetworkPolicyViolation("redirect_loop_blocked")
            redirects.append(next_url)
            current = next_url
            if response.status_code == 303:
                method = "GET"

    async def _await_request(
        self,
        url: str,
        method: Literal["HEAD", "GET"],
        timeout: float,
        cancellation_check: CancellationCheck | None,
    ) -> SecureHttpResponse:
        task = asyncio.create_task(self._single_request(url, method))
        deadline = time.monotonic() + timeout
        try:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError
                done, _ = await asyncio.wait({task}, timeout=min(0.2, remaining))
                if done:
                    return task.result()
                if cancellation_check and await cancellation_check():
                    raise asyncio.CancelledError
        finally:
            if not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

    async def _single_request(self, url: str, method: Literal["HEAD", "GET"]) -> SecureHttpResponse:
        if self._requests >= self.policy.maximum_requests:
            raise NetworkPolicyViolation("request_limit_exceeded")
        validated = validate_url(url, self.policy)
        parsed = validated.parsed
        hostname = parsed.hostname or ""
        resolved = await self.resolver.resolve(hostname, validated.port)
        delay = 1 / self.policy.maximum_requests_per_second
        wait_for = self._last_request_at + delay - time.monotonic()
        if wait_for > 0:
            await asyncio.sleep(wait_for)
        self._requests += 1
        self._last_request_at = time.monotonic()
        peer_ip = resolved.addresses[0]
        ssl_context = ssl.create_default_context() if parsed.scheme == "https" else None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    host=peer_ip,
                    port=validated.port,
                    ssl=ssl_context,
                    server_hostname=hostname if ssl_context else None,
                ),
                timeout=self.policy.connect_timeout,
            )
        except (OSError, ssl.SSLError, TimeoutError) as exc:
            raise NetworkPolicyViolation("connection_failed") from exc
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        host_header = hostname
        default_port = 443 if parsed.scheme == "https" else 80
        if validated.port != default_port:
            host_header = f"{host_header}:{validated.port}"
        request_bytes = (
            f"{method} {path} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            f"User-Agent: {self.policy.user_agent}\r\n"
            "Accept: text/html,application/json,text/plain;q=0.9,*/*;q=0.1\r\n"
            "Accept-Encoding: identity\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        try:
            writer.write(request_bytes)
            await writer.drain()
            header_block = await asyncio.wait_for(
                reader.readuntil(b"\r\n\r\n"), timeout=self.policy.read_timeout
            )
            if len(header_block) > 65_536:
                raise NetworkPolicyViolation("response_headers_too_large")
            status_code, reason, headers = _parse_headers(header_block)
            body = b""
            if method == "GET":
                body = await asyncio.wait_for(
                    reader.read(self.policy.maximum_response_bytes + 1),
                    timeout=self.policy.read_timeout,
                )
                if len(body) > self.policy.maximum_response_bytes:
                    raise NetworkPolicyViolation("response_body_too_large")
                length = first_header(headers, "content-length")
                if length and int(length) > self.policy.maximum_response_bytes:
                    raise NetworkPolicyViolation("response_body_too_large")
            received = len(header_block) + len(body)
            adapter_requests.labels(scheme=parsed.scheme).inc()
            adapter_bytes.labels(scheme=parsed.scheme).inc(received)
            return SecureHttpResponse(
                requested_url=url,
                final_url=url,
                status_code=status_code,
                reason=reason,
                headers=headers,
                body=body,
                peer_ip=peer_ip,
                request_count=self._requests,
                bytes_received=received,
                duration_ms=0,
            )
        except NetworkPolicyViolation:
            raise
        except (asyncio.IncompleteReadError, ValueError) as exc:
            raise NetworkPolicyViolation("invalid_http_response") from exc
        finally:
            writer.close()
            await writer.wait_closed()


def _parse_headers(data: bytes) -> tuple[int, str, dict[str, list[str]]]:
    text = data.decode("iso-8859-1")
    lines = text.split("\r\n")
    parts = lines[0].split(" ", 2)
    if len(parts) < 2 or not parts[0].startswith("HTTP/"):
        raise ValueError("invalid status line")
    status = int(parts[1])
    reason = parts[2] if len(parts) == 3 else ""
    headers: dict[str, list[str]] = {}
    for line in lines[1:]:
        if not line:
            continue
        if line[0].isspace() or ":" not in line:
            raise ValueError("invalid header")
        name, value = line.split(":", 1)
        key = name.strip().lower()
        headers.setdefault(key, []).append(value.strip())
    return status, reason, headers


def first_header(headers: dict[str, list[str]], name: str) -> str | None:
    values = headers.get(name.lower())
    return values[0] if values else None


def build_network_policy(
    *,
    category: str,
    profile_timeout: int,
    laboratory_mode: bool,
) -> NetworkExecutionPolicy:
    """Calculate immutable limits server-side; job configuration cannot raise them."""

    limits: dict[str, tuple[int, int, int]] = {
        "asset_inventory": (4, 131_072, 1),
        "dns_assessment": (12, 65_536, 0),
        "tls_assessment": (3, 131_072, 0),
        "http_security_headers": (4, 131_072, 2),
        "web_technology_detection": (3, 262_144, 1),
        "public_configuration": (3, 131_072, 1),
        "host_discovery": (32, 32_768, 0),
        "port_discovery": (32, 32_768, 0),
        "service_identification": (32, 65_536, 0),
    }
    discovery_ports = (
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
    )
    allowed_ports = (
        discovery_ports
        if category in {"host_discovery", "port_discovery", "service_identification"}
        else (80, 443, 8080, 8443)
    )
    requests, response_bytes, redirects = limits.get(category, (2, 65_536, 0))
    total = min(max(float(profile_timeout), 3.0), 120.0)
    return NetworkExecutionPolicy(
        maximum_requests=requests,
        maximum_requests_per_second=2.0,
        maximum_response_bytes=response_bytes,
        maximum_redirects=redirects,
        connect_timeout=min(5.0, total),
        read_timeout=min(10.0, total),
        total_timeout=total,
        allowed_schemes=("https", "http"),
        allowed_ports=allowed_ports,
        allow_private_addresses=laboratory_mode,
        allow_public_addresses=not laboratory_mode,
        resolve_once=True,
        deny_scope_expansion=True,
    )
