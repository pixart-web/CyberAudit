from cyberaudit.main import app
from cyberaudit.tracing import trace_context


def test_hardening_openapi_contains_operational_routes() -> None:
    routes = set(app.openapi()["paths"])
    assert {
        "/api/v1/auth/oidc/start",
        "/api/v1/auth/oidc/callback",
        "/api/v1/auth/mfa/totp/enroll",
        "/api/v1/auth/mfa/recovery-codes",
        "/api/v1/auth/sessions",
        "/api/v1/auth/sessions/{session_id}",
        "/api/v1/feature-flags",
        "/api/v1/license",
        "/api/v1/telemetry/preview",
        "/api/v1/telemetry",
        "/api/v1/operations/health",
        "/api/v1/operations/backups",
        "/api/v1/operations/restores",
        "/api/v1/operations/slos",
        "/api/v1/auth/webauthn/registration/options",
        "/api/v1/auth/webauthn/registration/verify",
        "/api/v1/auth/webauthn/step-up/options",
        "/api/v1/auth/webauthn/step-up/verify",
        "/api/v1/auth/webauthn/credentials/{factor_id}",
        "/api/v1/operations/dead-letters",
        "/api/v1/operations/dead-letters/{message_id}",
        "/api/v1/operations/dead-letters/{message_id}/{action}",
        "/api/v1/operations/production-readiness",
    } <= routes


def test_trace_context_preserves_valid_trace_and_rejects_invalid_values() -> None:
    incoming = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
    valid = trace_context(incoming)
    assert valid.trace_id == "4bf92f3577b34da6a3ce929d0e0e4736"
    assert valid.sampled is True
    assert valid.child_header().startswith(f"00-{valid.trace_id}-")
    invalid = trace_context("00-" + ("0" * 32) + "-" + ("0" * 16) + "-01")
    assert invalid.trace_id != "0" * 32
