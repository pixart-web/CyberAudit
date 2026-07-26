import asyncio

import pytest

from cyberaudit.network_security import (
    DnsRebindingBlocked,
    NetworkExecutionPolicy,
    NetworkPolicyViolation,
    SecureDnsResolver,
    SecureHttpClient,
    normalize_hostname,
    validate_ip_address,
    validate_url,
)


def policy(**updates):
    base = NetworkExecutionPolicy(
        allowed_ports=(80, 443),
        allow_private_addresses=False,
        allow_public_addresses=True,
    )
    return base.model_copy(update=updates)


def test_normalizes_idn_hostname():
    assert normalize_hostname("Exämple.test.") == "xn--exmple-cua.test"


@pytest.mark.parametrize("hostname", ["", "-bad.test", "bad_.test", "a..test"])
def test_rejects_invalid_hostname(hostname):
    with pytest.raises(NetworkPolicyViolation):
        normalize_hostname(hostname)


@pytest.mark.parametrize(
    ("url", "reason"),
    [
        ("ftp://example.test/", "url_scheme_blocked"),
        ("https://user:pass@example.test/", "url_credentials_blocked"),
        ("https://example.test:22/", "url_port_blocked"),
    ],
)
def test_url_policy_blocks_unsafe_forms(url, reason):
    with pytest.raises(NetworkPolicyViolation, match=reason):
        validate_url(url, policy())


@pytest.mark.parametrize(
    ("address", "reason"),
    [
        ("169.254.169.254", "cloud_metadata_address_blocked"),
        ("169.254.1.1", "link_local_address_blocked"),
        ("224.0.0.1", "multicast_address_blocked"),
        ("0.0.0.0", "unspecified_address_blocked"),  # noqa: S104 - validation fixture
        ("127.0.0.1", "loopback_address_blocked"),
        ("10.0.0.1", "private_address_blocked"),
        ("fd00:ec2::254", "cloud_metadata_address_blocked"),
    ],
)
def test_blocks_special_and_private_addresses(address, reason):
    with pytest.raises(NetworkPolicyViolation, match=reason):
        validate_ip_address(address, policy())


def test_allows_explicit_private_policy():
    assert str(validate_ip_address("10.0.0.1", policy(allow_private_addresses=True))) == "10.0.0.1"


@pytest.mark.asyncio
async def test_resolver_caches_exact_resolution():
    calls = 0

    async def lookup(_hostname, _port):
        nonlocal calls
        calls += 1
        return ["93.184.216.34"]

    resolver = SecureDnsResolver(
        policy(),
        ["example.test"],
        lookup,
    )
    first = await resolver.resolve("example.test", 443)
    second = await resolver.resolve("example.test", 443)
    assert first.addresses == ["93.184.216.34"]
    assert second.cached is True
    assert calls == 1


@pytest.mark.asyncio
async def test_dns_rebinding_is_blocked():
    answers = iter([["93.184.216.34"], ["93.184.216.35"]])

    async def lookup(_hostname, _port):
        return next(answers)

    resolver = SecureDnsResolver(policy(), ["example.test"], lookup)
    await resolver.resolve("example.test", 443)
    with pytest.raises(DnsRebindingBlocked):
        await resolver.resolve("example.test", 443, revalidate=True)


@pytest.mark.asyncio
async def test_literal_ip_outside_scope_is_blocked():
    async def lookup(_hostname, _port):
        return ["93.184.216.34"]

    resolver = SecureDnsResolver(policy(), ["198.51.100.10"], lookup)
    with pytest.raises(NetworkPolicyViolation, match="resolved_address_out_of_scope"):
        await resolver.resolve("93.184.216.34", 443)


async def _start_http_server(response_for_path):
    async def handler(reader, writer):
        request = await reader.readuntil(b"\r\n\r\n")
        path = request.split(b" ", 2)[1].decode()
        response = response_for_path(path)
        writer.write(response)
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    return server, port


@pytest.mark.asyncio
async def test_http_client_returns_limited_structured_response():
    server, port = await _start_http_server(
        lambda _path: b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-Test: yes\r\n\r\nok"
    )

    async def lookup(_hostname, _port):
        return ["127.0.0.1"]

    local_policy = policy(
        allowed_ports=(port,),
        allow_private_addresses=True,
        allow_public_addresses=False,
        maximum_response_bytes=1024,
    )
    resolver = SecureDnsResolver(local_policy, ["localhost"], lookup)
    try:
        response = await SecureHttpClient(local_policy, ["localhost"], resolver).request(
            f"http://localhost:{port}/", method="GET"
        )
    finally:
        server.close()
        await server.wait_closed()
    assert response.status_code == 200
    assert response.body == b"ok"
    assert response.peer_ip == "127.0.0.1"


@pytest.mark.asyncio
async def test_http_response_above_limit_is_blocked():
    body = b"x" * 2048
    server, port = await _start_http_server(
        lambda _path: (f"HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\n\r\n".encode() + body)
    )

    async def lookup(_hostname, _port):
        return ["127.0.0.1"]

    local_policy = policy(
        allowed_ports=(port,),
        allow_private_addresses=True,
        allow_public_addresses=False,
        maximum_response_bytes=1024,
    )
    try:
        with pytest.raises(NetworkPolicyViolation, match="response_body_too_large"):
            await SecureHttpClient(
                local_policy,
                ["localhost"],
                SecureDnsResolver(local_policy, ["localhost"], lookup),
            ).request(f"http://localhost:{port}/", method="GET")
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_redirect_to_destination_outside_scope_is_blocked():
    server, port = await _start_http_server(
        lambda _path: b"HTTP/1.1 302 Found\r\nLocation: http://outside.test/\r\n\r\n"
    )

    async def lookup(hostname, _port):
        return ["127.0.0.1"] if hostname == "localhost" else ["93.184.216.34"]

    local_policy = policy(
        allowed_ports=(80, port),
        allow_private_addresses=True,
        maximum_redirects=2,
    )
    try:
        with pytest.raises(NetworkPolicyViolation, match="resolved_address_out_of_scope"):
            await SecureHttpClient(
                local_policy,
                ["localhost"],
                SecureDnsResolver(local_policy, ["localhost"], lookup),
            ).request(f"http://localhost:{port}/")
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_http_cancellation_before_request():
    async def cancelled():
        return True

    with pytest.raises(asyncio.CancelledError):
        await SecureHttpClient(policy(), ["example.test"]).request(
            "https://example.test/", cancellation_check=cancelled
        )
