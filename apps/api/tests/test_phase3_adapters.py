import asyncio

from cyberaudit.adapters import (
    AdapterExecutionContext,
    AdapterRegistry,
    AdapterRequest,
    NormalizedTarget,
)
from cyberaudit.models import Intensity, TargetType
from cyberaudit.network_security import NetworkExecutionPolicy, SecureDnsResolver, SecureHttpClient
from cyberaudit.phase3_adapters import (
    HttpSecurityHeadersAdapter,
    PublicConfigurationAdapter,
)


async def _not_cancelled():
    return False


async def _progress(_value, _message):
    return None


def test_registry_contains_only_allowlisted_phase3_adapters():
    codes = {item.code for item in AdapterRegistry().metadata()}
    assert {
        "cyberaudit.asset_inventory",
        "cyberaudit.dns_assessment",
        "cyberaudit.tls_assessment",
        "cyberaudit.http_security_headers",
        "cyberaudit.web_technology_detection",
        "cyberaudit.public_configuration",
        "cyberaudit.external_result_import",
    }.issubset(codes)


async def test_phase3_configuration_rejects_extra_fields():
    adapter = HttpSecurityHeadersAdapter()
    result = await adapter.validate_configuration(
        {"scheme": "http", "path": "/", "fallback_get": True, "command": "curl"}
    )
    assert result.valid is False


async def _start_server():
    async def handler(reader, writer):
        request = await reader.readuntil(b"\r\n\r\n")
        method = request.split(b" ", 1)[0]
        if method == b"HEAD":
            response = (
                b"HTTP/1.1 405 Method Not Allowed\r\n"
                b"Content-Length: 0\r\n"
                b"Set-Cookie: session=secret; HttpOnly\r\n\r\n"
            )
        else:
            response = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Length: 2\r\n"
                b"Server: Lab/1.0\r\n"
                b"Set-Cookie: session=secret; HttpOnly\r\n\r\nok"
            )
        writer.write(response)
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1]


async def test_http_adapter_uses_head_fallback_and_sanitizes_cookie(monkeypatch):
    server, port = await _start_server()
    policy = NetworkExecutionPolicy(
        maximum_requests=4,
        maximum_response_bytes=4096,
        allowed_ports=(port,),
        allow_private_addresses=True,
        allow_public_addresses=False,
    )

    async def lookup(_hostname, _port):
        return ["127.0.0.1"]

    class InjectedClient(SecureHttpClient):
        def __init__(self, network_policy, allowed):
            super().__init__(
                network_policy,
                allowed,
                SecureDnsResolver(network_policy, allowed, lookup),
            )

    monkeypatch.setattr("cyberaudit.phase3_adapters.SecureHttpClient", InjectedClient)
    adapter = HttpSecurityHeadersAdapter()
    context = AdapterExecutionContext(
        execution_id="http-test",
        request=AdapterRequest(
            target=NormalizedTarget(
                target_type=TargetType.URL,
                value=f"http://localhost:{port}",
            ),
            technique="http-security-headers",
            intensity=Intensity.LOW,
            configuration={"scheme": "http", "path": "/", "fallback_get": True},
        ),
        progress_callback=_progress,
        cancellation_check=_not_cancelled,
        network_policy=policy,
        allowed_destinations=["localhost"],
    )
    try:
        result = await adapter.execute(context)
        parsed = await adapter.parse_output(result.raw_output)
    finally:
        server.close()
        await server.wait_closed()
    assert result.summary.simulated is False
    assert any(finding.source_identifier == "http.csp.missing" for finding in parsed.findings)
    assert "secret" not in parsed.evidence[0].content
    assert parsed.evidence[0].metadata["request_count"] == 2


async def test_public_configuration_only_accepts_declared_endpoint():
    adapter = PublicConfigurationAdapter()
    validation = await adapter.validate_configuration(
        {"scheme": "https", "endpoint": "/.git/config"}
    )
    assert validation.valid is False
