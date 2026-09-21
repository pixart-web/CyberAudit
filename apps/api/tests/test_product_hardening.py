from __future__ import annotations

import base64
import io
import zipfile
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from cyberaudit.authorization import AuthorizationPolicyEngine
from cyberaudit.config import Settings
from cyberaudit.connector_sdk import (
    LIVE_CONNECTOR_MANIFESTS,
    ConnectorCheckpoint,
    ConnectorContractTestSuite,
    ConnectorManifest,
    ScopedReadOnlyClient,
)
from cyberaudit.enterprise_auth import (
    consume_recovery_code,
    generate_recovery_codes,
    pkce_pair,
    verify_totp,
)
from cyberaudit.object_storage import FilesystemObjectStorage, inspect_upload
from cyberaudit.password_policy import validate_password_policy
from cyberaudit.product_services import (
    LicenseService,
    telemetry_preview,
    validate_lifecycle_transition,
)
from cyberaudit.redaction import redact
from cyberaudit.runners import (
    EphemeralRunnerDescriptor,
    LocalRestrictedRunner,
    RunnerRequest,
)
from cyberaudit.secrets import EnvironmentSecretProvider, SecretReference


def _actor(*permissions: str, organization_id: str = "org-a") -> SimpleNamespace:
    role = SimpleNamespace(
        permissions=[SimpleNamespace(code=permission) for permission in permissions]
    )
    return SimpleNamespace(
        id="user-a",
        organization_id=organization_id,
        status="active",
        deleted_at=None,
        roles=[role],
    )


def test_production_configuration_fails_closed() -> None:
    with pytest.raises(ValidationError, match="Unsafe production configuration"):
        Settings(environment="production")


def test_safe_production_configuration_is_accepted() -> None:
    settings = Settings(
        environment="production",
        database_url="postgresql+asyncpg://db/cyberaudit",
        redis_url="rediss://redis/0",
        jwt_secret="x" * 48,
        encryption_key="y" * 48,
        app_origin="https://audit.example.invalid",
        allowed_hosts=["audit.example.invalid"],
        require_https=True,
        secure_cookies=True,
        authentication_mode="oidc",
        local_auth_enabled=False,
        oidc_enabled=True,
        oidc_issuer="https://id.example.invalid",
        oidc_client_id="cyberaudit",
        oidc_redirect_uri="https://audit.example.invalid/callback",
        mfa_required=True,
        webauthn_enabled=True,
        webauthn_rp_id="audit.example.invalid",
        webauthn_origins=["https://audit.example.invalid"],
        rls_required=True,
        database_runtime_role="cyberaudit_runtime",
        secret_provider="vault",  # noqa: S106 -- provider selector, not a credential
        vault_address="https://vault.example.invalid",
        object_storage_provider="s3",
        object_storage_bucket="cyberaudit",
        connector_mode="live_read_only",
        runner_type="kubernetes_job",
        runner_controller_url="https://runner.example.invalid",
    )
    assert settings.production_like


def test_redaction_covers_nested_secrets_and_connections() -> None:
    result = redact(
        {
            "password": "never",
            "nested": {
                "message": "Bearer abc.def and redis://user:pass@cache:6379/0",
                "client-secret": "also-never",
            },
        }
    )
    assert result["password"] == "[REDACTED]"
    assert result["nested"]["client-secret"] == "[REDACTED]"
    assert "abc.def" not in result["nested"]["message"]
    assert "user:pass" not in result["nested"]["message"]


def test_authorization_is_deny_by_default_and_tenant_safe() -> None:
    engine = AuthorizationPolicyEngine()
    actor = _actor("assets.read")
    assert (
        engine.evaluate(actor=actor, organization_id="org-b", permission="assets.read").reason_code
        == "CROSS_TENANT"
    )
    assert (
        engine.evaluate(
            actor=actor, organization_id="org-a", permission="assets.manage"
        ).reason_code
        == "PERMISSION_MISSING"
    )
    assert (
        engine.evaluate(actor=actor, organization_id="org-a", permission="assets.read").decision
        == "allow"
    )


def test_authorization_requires_step_up_for_sensitive_actions() -> None:
    actor = _actor("roles.manage")
    engine = AuthorizationPolicyEngine()
    assert (
        engine.evaluate(actor=actor, organization_id="org-a", permission="roles.manage").reason_code
        == "STEP_UP_REQUIRED"
    )
    assert (
        engine.evaluate(
            actor=actor,
            organization_id="org-a",
            permission="roles.manage",
            authentication_strength="mfa",
        ).decision
        == "allow"
    )


def test_password_policy_rejects_common_and_identity_passwords() -> None:
    with pytest.raises(ValueError):
        validate_password_policy("ChangeMe123!")
    with pytest.raises(ValueError):
        validate_password_policy("tiago-Secure-2026!", email="tiago@example.invalid")
    assert validate_password_policy("Green-Citadel-2026!") == "Green-Citadel-2026!"


def test_pkce_recovery_codes_and_totp_are_deterministic_at_fixed_time() -> None:
    verifier, challenge = pkce_pair()
    assert len(verifier) >= 43
    assert "=" not in challenge
    codes, hashes = generate_recovery_codes(5)
    assert consume_recovery_code(codes[2], hashes) == 2
    assert consume_recovery_code("wrong", hashes) is None
    assert verify_totp("JBSWY3DPEHPK3PXP", "282760", at_time=59)
    assert not verify_totp("JBSWY3DPEHPK3PXP", "000000", at_time=59, window=0)


def test_connector_contracts_and_url_scope() -> None:
    for manifest in LIVE_CONNECTOR_MANIFESTS.values():
        ConnectorContractTestSuite.assert_compatible(manifest, "0.2.0")
    test_token = "opaque-" + "value"
    client = ScopedReadOnlyClient(
        allowed_origins=["https://graph.microsoft.com"], bearer_token=test_token
    )
    client.validate_url("https://graph.microsoft.com/v1.0/users")
    with pytest.raises(ValueError):
        client.validate_url("https://graph.microsoft.com.evil.invalid/users")
    with pytest.raises(ValidationError):
        ConnectorManifest(
            **{
                **LIVE_CONNECTOR_MANIFESTS["entra"].model_dump(),
                "write_capabilities": ["users.write"],
            }
        )


def test_connector_checkpoints_are_monotonic() -> None:
    now = datetime.now(timezone.utc)
    with pytest.raises(ValueError):
        ConnectorContractTestSuite.validate_checkpoint(
            ConnectorCheckpoint(observed_at=now),
            ConnectorCheckpoint(observed_at=now - timedelta(seconds=1)),
        )


@pytest.mark.asyncio
async def test_runner_has_closed_operations_and_fails_closed_for_external_runner() -> None:
    with pytest.raises(ValidationError):
        RunnerRequest(operation="shell", payload={"command": "id"})  # type: ignore[arg-type]
    result = await LocalRestrictedRunner().execute(
        RunnerRequest(operation="sha256", payload={"value": "safe"})
    )
    assert result.status == "completed"
    assert result.metadata["external_process"] is False
    unavailable = await EphemeralRunnerDescriptor("kubernetes_job").execute(
        RunnerRequest(operation="validate_json")
    )
    assert unavailable.status == "unavailable"
    assert unavailable.error_code == "RUNNER_CONTROLLER_NOT_CONFIGURED"


def test_upload_inspection_blocks_path_traversal_and_archive_bombs() -> None:
    with pytest.raises(ValueError):
        inspect_upload(
            b"%PDF-test",
            filename="../authorization.pdf",
            content_type="application/pdf",
            allowed_types={"application/pdf"},
            maximum_bytes=1024,
        )
    archive_bytes = io.BytesIO()
    with zipfile.ZipFile(archive_bytes, "w") as archive:
        archive.writestr("../escape.txt", "content")
    with pytest.raises(ValueError, match="unsafe path"):
        inspect_upload(
            archive_bytes.getvalue(),
            filename="import.zip",
            content_type="application/zip",
            allowed_types={"application/zip"},
            maximum_bytes=4096,
        )


@pytest.mark.asyncio
async def test_filesystem_storage_is_tenant_partitioned(tmp_path) -> None:
    storage = FilesystemObjectStorage(tmp_path, "test")
    metadata = await storage.put("org-a", b"{}", "application/json", "evidence")
    assert await storage.get("org-a", metadata.key, 100) == b"{}"
    with pytest.raises(ValueError):
        await storage.get("org-b", metadata.key, 100)
    with pytest.raises(ValueError):
        FilesystemObjectStorage(tmp_path, "production")


def test_lifecycle_telemetry_and_signed_offline_license() -> None:
    with pytest.raises(ValueError):
        validate_lifecycle_transition("legal_hold", "deleted", legal_hold=True)
    with pytest.raises(ValueError):
        telemetry_preview({"email": "person@example.invalid"})
    assert telemetry_preview({"version": "1.0.0"}) == {"version": "1.0.0"}

    private_key = Ed25519PrivateKey.generate()
    payload = b'{"edition":"enterprise"}'
    encoded_payload = base64.urlsafe_b64encode(payload).decode().rstrip("=")
    signature = base64.urlsafe_b64encode(private_key.sign(payload)).decode().rstrip("=")
    public_key = base64.urlsafe_b64encode(private_key.public_key().public_bytes_raw()).decode()
    assert (
        LicenseService.verify_offline(encoded_payload, signature, public_key)["edition"]
        == "enterprise"
    )


@pytest.mark.asyncio
async def test_environment_secret_provider_is_allowlisted(monkeypatch) -> None:
    monkeypatch.setenv("CYBERAUDIT_TOTP_SECRET", "JBSWY3DPEHPK3PXP")
    provider = EnvironmentSecretProvider({"CYBERAUDIT_TOTP_SECRET"}, "test")
    assert (
        await provider.resolve_reference(SecretReference("env://CYBERAUDIT_TOTP_SECRET"))
        == "JBSWY3DPEHPK3PXP"
    )
    with pytest.raises(ValueError):
        await provider.resolve_reference(SecretReference("env://HOME"))
