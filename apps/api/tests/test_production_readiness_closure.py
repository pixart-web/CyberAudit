from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from io import BytesIO

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from cyberaudit.config import Settings
from cyberaudit.dead_letter import DeadLetterEnvelope, DeadLetterService
from cyberaudit.enterprise_auth import OidcClient, OidcTransaction
from cyberaudit.hardening_models import (
    ProductionReadinessApproval,
    ProductionReadinessEvidence,
)
from cyberaudit.models import Organization, User
from cyberaudit.object_storage import S3ObjectStorage
from cyberaudit.readiness import MANDATORY_CHECKS, ProductionReadinessGate
from cyberaudit.rls import require_tenant_context, set_tenant_context
from cyberaudit.runners import EphemeralRunnerController, RunnerRequest
from cyberaudit.secrets import SecretReference, VaultSecretProvider
from cyberaudit.webauthn_service import WebAuthnChallengeStore, WebAuthnService


class FakeRedis:
    def __init__(self) -> None:
        self.values: dict[str, str] = {}

    async def set(self, key: str, value: str, **_: object) -> bool:
        if key in self.values:
            return False
        self.values[key] = value
        return True

    async def getdel(self, key: str) -> str | None:
        return self.values.pop(key, None)


class FakeS3:
    def __init__(self) -> None:
        self.objects: dict[str, dict[str, object]] = {}

    def put_object(self, **kwargs: object) -> None:
        self.objects[str(kwargs["Key"])] = kwargs

    def get_object(self, **kwargs: object) -> dict[str, object]:
        stored = self.objects[str(kwargs["Key"])]
        body = bytes(stored["Body"])
        return {
            "Body": BytesIO(body),
            "ContentLength": len(body),
            "Metadata": stored["Metadata"],
        }

    def delete_object(self, **kwargs: object) -> None:
        self.objects.pop(str(kwargs["Key"]), None)

    def generate_presigned_url(self, *_: object, **kwargs: object) -> str:
        return f"https://storage.example.invalid/{kwargs['Params']['Key']}"

    def head_bucket(self, **_: object) -> None:
        return None


async def _identity(db):
    organization = Organization(name="Tenant A", slug="tenant-a")
    db.add(organization)
    await db.flush()
    user = User(
        organization_id=organization.id,
        name="Operator",
        email="operator@tenant-a.invalid",
        password_hash="not-used",  # noqa: S106 -- inert fixture value
    )
    db.add(user)
    await db.flush()
    return organization, user


@pytest.mark.asyncio
async def test_tenant_context_is_required_and_rejects_mismatch(db) -> None:
    organization, _ = await _identity(db)
    with pytest.raises(PermissionError):
        await require_tenant_context(db, organization.id)
    await set_tenant_context(db, organization.id)
    await require_tenant_context(db, organization.id)
    with pytest.raises(PermissionError):
        await require_tenant_context(db, "00000000-0000-4000-8000-000000000099")
    with pytest.raises(ValueError):
        await set_tenant_context(db, "frontend-controlled")


@pytest.mark.asyncio
async def test_webauthn_challenge_is_single_use_tenant_and_purpose_bound() -> None:
    store = WebAuthnChallengeStore("redis://unused", 300)
    store.client = FakeRedis()  # type: ignore[assignment]
    organization_id = "00000000-0000-4000-8000-000000000001"
    user_id = "00000000-0000-4000-8000-000000000002"
    challenge = await store.create(organization_id, user_id, "step_up")
    consumed = await store.consume(organization_id, user_id, challenge.challenge_id, "step_up")
    assert consumed.challenge == challenge.challenge
    with pytest.raises(ValueError, match="already used"):
        await store.consume(organization_id, user_id, challenge.challenge_id, "step_up")

    wrong_purpose = await store.create(organization_id, user_id, "registration")
    with pytest.raises(ValueError, match="context mismatch"):
        await store.consume(organization_id, user_id, wrong_purpose.challenge_id, "step_up")


@pytest.mark.asyncio
async def test_webauthn_options_exclude_existing_public_credentials(db) -> None:
    _, user = await _identity(db)
    store = WebAuthnChallengeStore("redis://unused", 300)
    store.client = FakeRedis()  # type: ignore[assignment]
    service = WebAuthnService(
        Settings(
            environment="test",
            webauthn_enabled=True,
            webauthn_rp_id="localhost",
            webauthn_origins=["http://localhost:3000"],
        ),
        store,
    )
    challenge_id, options = await service.registration_options(db, user)
    assert challenge_id
    assert options["rp"]["id"] == "localhost"
    assert options["user"]["name"] == user.email
    assert options["authenticatorSelection"]["userVerification"] == "required"


@pytest.mark.asyncio
async def test_dead_letter_capture_deduplicates_and_replay_requires_step_up(db) -> None:
    organization, user = await _identity(db)
    await set_tenant_context(db, organization.id)
    envelope = DeadLetterEnvelope(
        organization_id=organization.id,
        queue_name="connector_sync",
        message_type="connector.sync",
        message_id="message-0001",
        idempotency_key="idempotency-0001",
        payload_reference="object://opaque-reference-0001",
        error_code="PROVIDER_TIMEOUT",
        error_summary="Provider did not answer; token=secret-value",
    )
    replayed: list[str] = []

    async def replay(message) -> None:
        replayed.append(message.id)

    service = DeadLetterService({"connector_sync": replay})
    message = await service.capture(db, envelope)
    duplicate = await service.capture(db, envelope)
    assert duplicate.id == message.id
    assert duplicate.attempts == 2
    assert "secret-value" not in duplicate.error_summary
    with pytest.raises(PermissionError):
        await service.transition(
            db,
            message,
            action="replay",
            actor_id=user.id,
            step_up_verified=False,
        )
    await service.transition(
        db,
        message,
        action="replay",
        actor_id=user.id,
        step_up_verified=True,
    )
    assert message.status == "replayed"
    assert message.replay_count == 1
    assert replayed == [message.id]


@pytest.mark.asyncio
async def test_dead_letter_cross_tenant_and_unknown_queue_are_denied(db) -> None:
    organization, _ = await _identity(db)
    await set_tenant_context(db, organization.id)
    foreign = DeadLetterEnvelope(
        organization_id="00000000-0000-4000-8000-000000000099",
        queue_name="connector_sync",
        message_type="connector.sync",
        message_id="message-foreign",
        idempotency_key="idempotency-foreign",
        payload_reference="object://opaque-reference-foreign",
        error_code="FAILED",
        error_summary="Synthetic failure",
    )
    with pytest.raises(PermissionError):
        await DeadLetterService().capture(db, foreign)
    invalid = foreign.model_copy(
        update={"organization_id": organization.id, "queue_name": "arbitrary_queue"}
    )
    with pytest.raises(ValueError, match="not registered"):
        await DeadLetterService().capture(db, invalid)


@pytest.mark.asyncio
async def test_readiness_gate_never_auto_approves(db) -> None:
    organization, user = await _identity(db)
    await set_tenant_context(db, organization.id)
    gate = ProductionReadinessGate(Settings(environment="test"), "10.1.0-rc.1")
    initial = await gate.evaluate(db, organization.id, "production-like")
    assert initial["state"] == "incomplete"
    assert set(initial["blockers"]) == set(MANDATORY_CHECKS)

    observed_at = datetime.now(timezone.utc)
    for code in MANDATORY_CHECKS:
        db.add(
            ProductionReadinessEvidence(
                organization_id=organization.id,
                check_code=code,
                status="passed",
                summary="Synthetic controlled evidence",
                evidence_references=[f"evidence://{code}"],
                details={"contains_secrets": False},
                environment="production-like",
                application_version="10.1.0-rc.1",
                observed_at=observed_at,
                expires_at=observed_at + timedelta(days=1),
                recorded_by=user.id,
            )
        )
    await db.flush()
    candidate = await gate.evaluate(db, organization.id, "production-like")
    assert candidate["state"] == "candidate"
    assert candidate["formal_approval_required"] is True

    db.add(
        ProductionReadinessApproval(
            organization_id=organization.id,
            environment="production-like",
            status="approved",
            decision="approved",
            requested_by=user.id,
            reviewed_by=user.id,
            reviewed_at=datetime.now(timezone.utc),
            notes=json.dumps({"formal": True}),
        )
    )
    await db.flush()
    approved = await gate.evaluate(db, organization.id, "production-like")
    assert approved["state"] == "approved"


@pytest.mark.asyncio
async def test_vault_provider_uses_closed_reference_and_workload_token(tmp_path) -> None:
    token_file = tmp_path / "vault-token"
    token_file.write_text("workload-token", encoding="utf-8")
    observed: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        observed.append(request)
        assert request.headers["X-Vault-Token"] == "workload-token"
        if request.url.path.endswith("/metadata/apps/cyberaudit"):
            return httpx.Response(200, json={"data": {"current_version": 7}})
        if request.url.path == "/v1/sys/health":
            return httpx.Response(200, json={"initialized": True, "sealed": False})
        return httpx.Response(
            200,
            json={"data": {"data": {"client_secret": "resolved-secret"}}},
        )

    provider = VaultSecretProvider(
        "https://vault.example.invalid",
        token_file,
        transport=httpx.MockTransport(handler),
    )
    reference = SecretReference("vault://secret/apps/cyberaudit?version=7#client_secret")
    assert await provider.resolve_reference(reference) == "resolved-secret"
    metadata = await provider.get_metadata(reference)
    assert metadata.available is True
    assert metadata.version == "7"
    assert (await provider.health_check()).healthy is True
    assert all(not request.extensions.get("follow_redirects", False) for request in observed)
    with pytest.raises(ValueError):
        provider.validate_reference(SecretReference("vault://secret/../root#password"))


@pytest.mark.asyncio
async def test_s3_storage_partitions_tenants_and_checks_integrity() -> None:
    client = FakeS3()
    tenant = "00000000-0000-4000-8000-000000000001"
    foreign_tenant = "00000000-0000-4000-8000-000000000099"
    storage = S3ObjectStorage(
        "cyberaudit",
        "eu-west-1",
        client=client,
        environment="test",
    )
    metadata = await storage.put(tenant, b"evidence", "application/octet-stream", "evidence")
    assert metadata.key.startswith(f"organizations/{tenant}/evidence/")
    assert await storage.get(tenant, metadata.key, 100) == b"evidence"
    assert (await storage.health_check())["healthy"] is True
    assert await storage.create_download_url(tenant, metadata.key, 60) == (
        f"https://storage.example.invalid/{metadata.key}"
    )
    with pytest.raises(ValueError, match="tenant partition"):
        await storage.get(foreign_tenant, metadata.key, 100)
    client.objects[metadata.key]["Metadata"] = {"sha256": "0" * 64}
    with pytest.raises(ValueError, match="checksum"):
        await storage.get(tenant, metadata.key, 100)


def test_ephemeral_runner_spec_is_immutable_and_hardened(tmp_path) -> None:
    token_file = tmp_path / "runner-token"
    token_file.write_text("workload-token", encoding="utf-8")
    runner = EphemeralRunnerController(
        "kubernetes_job",
        "https://runner.example.invalid",
        token_file,
    )
    spec = runner.build_spec(RunnerRequest(operation="sha256", payload={"value": "safe"}))
    assert "@sha256:" in spec["image"]
    assert "command" not in spec
    assert "args" not in spec
    assert spec["security"]["read_only_filesystem"] is True
    assert spec["security"]["drop_capabilities"] == ["ALL"]
    assert spec["security"]["network_mode"] == "none"
    assert spec["security"]["docker_socket_mounted"] is False


@pytest.mark.asyncio
async def test_oidc_protocol_validates_signature_nonce_email_and_role_mapping() -> None:
    issuer = "https://identity.example.invalid"
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private_key.public_key()))
    public_jwk.update({"kid": "rotated-key", "use": "sig", "alg": "RS256"})
    now = datetime.now(timezone.utc)
    settings = Settings(
        environment="test",
        oidc_enabled=True,
        oidc_issuer=issuer,
        oidc_client_id="cyberaudit",
        oidc_redirect_uri="https://audit.example.invalid/auth/callback",
        oidc_allowed_domains=["example.invalid"],
        oidc_required_group="CyberAudit-Analyst",
    )
    transaction = OidcTransaction(
        state="single-use-state",
        nonce="expected-nonce",
        verifier_hash=hashlib.sha256(b"verifier").hexdigest(),
        organization_id="00000000-0000-4000-8000-000000000001",
        expires_at=now + timedelta(minutes=5),
    )

    def claims(email_verified: bool = True) -> dict[str, object]:
        return {
            "iss": issuer,
            "aud": "cyberaudit",
            "sub": "subject-1",
            "nonce": "expected-nonce",
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(minutes=5)).timestamp()),
            "email": "auditor@example.invalid",
            "email_verified": email_verified,
            "groups": ["CyberAudit-Analyst"],
        }

    encoded = jwt.encode(
        claims(),
        private_key,
        algorithm="RS256",
        headers={"kid": "rotated-key"},
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/.well-known/openid-configuration"):
            return httpx.Response(
                200,
                json={
                    "issuer": issuer,
                    "authorization_endpoint": f"{issuer}/authorize",
                    "token_endpoint": f"{issuer}/token",
                    "jwks_uri": f"{issuer}/jwks",
                },
            )
        if request.url.path.endswith("/token"):
            return httpx.Response(200, json={"id_token": encoded})
        return httpx.Response(200, json={"keys": [public_jwk]})

    client = OidcClient(settings, transport=httpx.MockTransport(handler))
    validated = await client.exchange_and_validate(
        code="one-time-code",
        verifier="verifier",
        transaction=transaction,
    )
    assert validated["sub"] == "subject-1"
    assert client.mapped_roles(validated) == {"Auditor"}

    unverified_token = jwt.encode(
        claims(False),
        private_key,
        algorithm="RS256",
        headers={"kid": "rotated-key"},
    )

    def unverified_handler(request: httpx.Request) -> httpx.Response:
        response = handler(request)
        if request.url.path.endswith("/token"):
            return httpx.Response(200, json={"id_token": unverified_token})
        return response

    unverified_client = OidcClient(
        settings,
        transport=httpx.MockTransport(unverified_handler),
    )
    with pytest.raises(ValueError, match="not verified"):
        await unverified_client.exchange_and_validate(
            code="one-time-code",
            verifier="verifier",
            transaction=transaction,
        )
