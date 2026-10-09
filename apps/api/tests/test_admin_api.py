"""Real user/tenant administration and first-run bootstrap."""

from __future__ import annotations

from collections.abc import AsyncIterator
from types import SimpleNamespace

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cyberaudit import admin_api
from cyberaudit.admin_api import ensure_rbac
from cyberaudit.db import get_db
from cyberaudit.main import app
from cyberaudit.models import AuditLog, Organization, Role, User
from cyberaudit.security import current_user, hash_password

STRONG = "Correct-Horse-Battery-9"


async def _tenant(db: AsyncSession, slug: str, role: str = "Administrator") -> User:
    org = Organization(name=f"Org {slug}", slug=slug)
    db.add(org)
    await db.flush()
    r = await db.scalar(select(Role).where(Role.name == role))
    user = User(
        organization_id=org.id,
        name=f"Admin {slug}",
        email=f"admin@{slug}.example.com",
        password_hash=hash_password(STRONG),
        roles=[r],
    )
    db.add(user)
    await db.flush()
    return user


class _Client:
    def __init__(self, db: AsyncSession, who: User | None):
        self.db, self.who = db, who
        self.who_id = who.id if who is not None else None

    async def __aenter__(self):
        async def override_db() -> AsyncIterator[AsyncSession]:
            yield self.db

        app.dependency_overrides[get_db] = override_db
        if self.who is not None:

            async def override_user() -> User:
                # Fresh instance per request, like a real per-request session.
                return await self.db.get(User, self.who_id, populate_existing=True)  # type: ignore[return-value]

            app.dependency_overrides[current_user] = override_user
        self.client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
            base_url="http://testserver",
        )
        return self.client

    async def __aexit__(self, *exc):
        await self.client.aclose()
        app.dependency_overrides.clear()


@pytest.fixture
async def rbac(db: AsyncSession) -> AsyncSession:
    await ensure_rbac(db)
    await db.commit()
    return db


@pytest.mark.asyncio
async def test_user_lifecycle_is_real_and_audited(rbac: AsyncSession):
    admin = await _tenant(rbac, "a")
    async with _Client(rbac, admin) as c:
        body = {
            "name": "Maria Silva",
            "email": "maria@a.example.com",
            "password": STRONG,
            "role": "Auditor",
        }
        created = await c.post("/api/v1/users", json=body)
        assert created.status_code == 201, created.text
        uid = created.json()["id"]
        assert (await c.post("/api/v1/users", json=body)).status_code == 409

        rr = await c.get("/api/v1/roles")
        assert rr.status_code == 200, rr.text
        roles = rr.json()["items"]
        assert "Platform Administrator" not in {r["name"] for r in roles}
        assert "Auditor" in {r["name"] for r in roles}

        patched = await c.patch(
            f"/api/v1/users/{uid}", json={"role": "Reviewer", "status": "disabled"}
        )
        assert patched.status_code == 200
        assert patched.json()["roles"] == ["Reviewer"] and patched.json()["status"] == "disabled"

        assert (
            await c.patch(f"/api/v1/users/{admin.id}", json={"status": "disabled"})
        ).status_code == 409
        assert (
            await c.patch(f"/api/v1/users/{admin.id}", json={"role": "Client"})
        ).status_code == 409
        assert (
            await c.patch(f"/api/v1/users/{uid}", json={"role": "Platform Administrator"})
        ).status_code == 403
        assert (await c.patch(f"/api/v1/users/{uid}", json={"role": "Nope"})).status_code == 422

        weak = await c.post(
            f"/api/v1/users/{uid}/reset-password", json={"password": "aaaaaaaaaaaaaaaa"}
        )
        assert weak.status_code == 422
        ok = await c.post(
            f"/api/v1/users/{uid}/reset-password", json={"password": "Another-Strong-Pass-7!"}
        )
        assert ok.status_code == 204
        assert (await c.post(f"/api/v1/users/{uid}/revoke-sessions")).status_code == 200

    user = await rbac.get(User, uid)
    assert user is not None and user.must_change_password is True
    actions = {a for (a,) in (await rbac.execute(select(AuditLog.action))).all()}
    assert {
        "user.created",
        "user.updated",
        "user.password_reset",
        "user.sessions_revoked",
    } <= actions


@pytest.mark.asyncio
async def test_cross_tenant_and_unauthorized_user_admin_denied(rbac: AsyncSession):
    admin_a = await _tenant(rbac, "a")
    admin_b = await _tenant(rbac, "b")
    auditor = await _tenant(rbac, "c", role="Auditor")
    async with _Client(rbac, admin_a) as c:
        assert (
            await c.patch(f"/api/v1/users/{admin_b.id}", json={"status": "disabled"})
        ).status_code == 404
        assert (
            await c.post(f"/api/v1/users/{admin_b.id}/reset-password", json={"password": STRONG})
        ).status_code == 404
        listed = (await c.get("/api/v1/users")).json()["items"]
        assert {u["email"] for u in listed} == {admin_a.email}
    async with _Client(rbac, auditor) as c:
        assert (
            await c.patch(f"/api/v1/users/{auditor.id}", json={"name": "Hacker"})
        ).status_code == 403
        assert (await c.get("/api/v1/roles")).status_code == 403
        assert (await c.post("/api/v1/platform/organizations", json={})).status_code == 403


@pytest.mark.asyncio
async def test_tenant_creation_requires_platform_permission(rbac: AsyncSession):
    plain = await _tenant(rbac, "a")
    platform = await _tenant(rbac, "p", role="Platform Administrator")
    payload = {
        "name": "Northstar Industries",
        "slug": "northstar",
        "admin_name": "Ana Costa",
        "admin_email": "ana@northstar.example.com",
        "admin_password": STRONG,
    }
    async with _Client(rbac, plain) as c:
        assert (await c.post("/api/v1/platform/organizations", json=payload)).status_code == 403
    async with _Client(rbac, platform) as c:
        created = await c.post("/api/v1/platform/organizations", json=payload)
        assert created.status_code == 201, created.text
        assert (await c.post("/api/v1/platform/organizations", json=payload)).status_code == 409
        bad = await c.post(
            "/api/v1/platform/organizations",
            json={
                **payload,
                "slug": "other",
                "admin_email": "x@y.example.com",
                "admin_password": "short",
            },
        )
        assert bad.status_code == 422
    new_admin = await rbac.scalar(select(User).where(User.email == "ana@northstar.example.com"))
    assert new_admin is not None
    assert new_admin.organization_id == created.json()["id"] != platform.organization_id
    assert new_admin.must_change_password is True


@pytest.mark.asyncio
async def test_bootstrap_is_token_gated_and_one_shot(
    db: AsyncSession, monkeypatch: pytest.MonkeyPatch
):
    token = "x" * 32
    payload = {
        "name": "Acme",
        "slug": "acme",
        "admin_name": "Root Admin",
        "admin_email": "root@acme.example.com",
        "admin_password": STRONG,
    }
    monkeypatch.setattr(admin_api, "get_settings", lambda: SimpleNamespace(bootstrap_token=None))
    async with _Client(db, None) as c:
        assert (await c.get("/api/v1/setup/status")).json() == {
            "initialized": False,
            "bootstrap_enabled": False,
        }
        assert (
            await c.post("/api/v1/setup/initialize", json={**payload, "bootstrap_token": token})
        ).status_code == 403

    monkeypatch.setattr(admin_api, "get_settings", lambda: SimpleNamespace(bootstrap_token=token))
    async with _Client(db, None) as c:
        assert (await c.get("/api/v1/setup/status")).json()["bootstrap_enabled"] is True
        wrong = await c.post(
            "/api/v1/setup/initialize", json={**payload, "bootstrap_token": "y" * 32}
        )
        assert wrong.status_code == 403
        ok = await c.post("/api/v1/setup/initialize", json={**payload, "bootstrap_token": token})
        assert ok.status_code == 201, ok.text
        again = await c.post("/api/v1/setup/initialize", json={**payload, "bootstrap_token": token})
        assert again.status_code == 403
        assert (await c.get("/api/v1/setup/status")).json() == {
            "initialized": True,
            "bootstrap_enabled": False,
        }
    root = await db.scalar(select(User).where(User.email == "root@acme.example.com"))
    assert root is not None and [r.name for r in root.roles] == ["Platform Administrator"]


@pytest.mark.asyncio
async def test_client_and_asset_update_archive_are_tenant_scoped(rbac: AsyncSession):
    from cyberaudit.models import Asset, Client, Criticality

    a = await _tenant(rbac, "a")
    b = await _tenant(rbac, "b")
    client_a = Client(organization_id=a.organization_id, name="Client A")
    client_b = Client(organization_id=b.organization_id, name="Client B")
    asset_a = Asset(
        organization_id=a.organization_id,
        engagement_id="e",
        name="srv",
        asset_type="host",
        identifier="srv",
        criticality=Criticality.LOW,
    )
    rbac.add_all([client_a, client_b, asset_a])
    await rbac.commit()
    async with _Client(rbac, a) as c:
        ok = await c.patch(
            f"/api/v1/clients/{client_a.id}", json={"name": "Client A2", "status": "inactive"}
        )
        assert ok.status_code == 200 and ok.json()["name"] == "Client A2"
        assert (
            await c.patch(f"/api/v1/clients/{client_b.id}", json={"name": "xx"})
        ).status_code == 404
        cleared = await c.patch(
            f"/api/v1/clients/{client_a.id}", json={"email": None, "phone": None}
        )
        assert cleared.status_code == 200 and cleared.json()["email"] is None
        assert (
            await c.patch(f"/api/v1/clients/{client_a.id}", json={"status": "weird"})
        ).status_code == 422
        assert (
            await c.patch(f"/api/v1/clients/{client_a.id}", json={"organization_id": "x"})
        ).status_code == 422
        assert (await c.delete(f"/api/v1/assets/{asset_a.id}")).status_code == 204
    async with _Client(rbac, b) as c:
        assert (await c.delete(f"/api/v1/assets/{asset_a.id}")).status_code == 404
    actions = {x for (x,) in (await rbac.execute(select(AuditLog.action))).all()}
    assert {"client.updated", "asset.archived"} <= actions


def _signed(private_key, document: dict) -> tuple[str, str]:
    import base64
    import json

    raw = json.dumps(document).encode()
    enc = lambda b: base64.urlsafe_b64encode(b).decode().rstrip("=")  # noqa: E731
    return enc(raw), enc(private_key.sign(raw))


@pytest.mark.asyncio
async def test_license_import_requires_trusted_key_matching_org_and_valid_dates(
    rbac: AsyncSession, monkeypatch: pytest.MonkeyPatch
):
    import base64

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key, rogue = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    pub = base64.urlsafe_b64encode(key.public_key().public_bytes_raw()).decode()
    admin = await _tenant(rbac, "a")
    other = await _tenant(rbac, "b")
    valid = {
        "edition": "professional",
        "license_id": "EVAL-001",
        "organization_id": admin.organization_id,
        "issued_at": "2026-10-01T00:00:00Z",
        "expires_at": "2099-01-01T00:00:00Z",
    }

    class _S:
        license_trusted_public_keys: list[str] = []

    monkeypatch.setattr(admin_api, "get_settings", lambda: _S())
    p, s = _signed(key, valid)
    async with _Client(rbac, admin) as c:
        # No trusted keys configured: refuse (never trust by default).
        assert (
            await c.post("/api/v1/license/import", json={"payload": p, "signature": s})
        ).status_code == 409
        _S.license_trusted_public_keys = [pub]
        assert (await c.get("/api/v1/license/summary")).json()["edition"] == "community"
        # Signed by an untrusted key.
        rp, rs = _signed(rogue, valid)
        assert (
            await c.post("/api/v1/license/import", json={"payload": rp, "signature": rs})
        ).status_code == 422
        # Tampered payload.
        assert (
            await c.post("/api/v1/license/import", json={"payload": p, "signature": rs})
        ).status_code == 422
        # Issued for another organization.
        op, os_ = _signed(key, {**valid, "organization_id": other.organization_id})
        assert (
            await c.post("/api/v1/license/import", json={"payload": op, "signature": os_})
        ).status_code == 422
        # Already expired.
        ep, es = _signed(key, {**valid, "expires_at": "2020-01-01T00:00:00Z"})
        assert (
            await c.post("/api/v1/license/import", json={"payload": ep, "signature": es})
        ).status_code == 422
        ok = await c.post("/api/v1/license/import", json={"payload": p, "signature": s})
        assert ok.status_code == 201, ok.text
        summary = (await c.get("/api/v1/license/summary")).json()
        assert (
            summary["edition"] == "professional"
            and summary["state"] == "active"
            and "soc" in summary["capabilities"]
        )
    async with _Client(rbac, other) as c:
        assert (await c.get("/api/v1/license/summary")).json()["edition"] == "community"
    actions = {x for (x,) in (await rbac.execute(select(AuditLog.action))).all()}
    assert {"license.imported", "license.import_rejected"} <= actions


@pytest.mark.asyncio
async def test_organization_edit_is_limited_to_own_org_and_validated(rbac: AsyncSession):
    a = await _tenant(rbac, "a")
    b = await _tenant(rbac, "b")
    async with _Client(rbac, a) as c:
        ok = await c.patch(
            f"/api/v1/organizations/{a.organization_id}",
            json={"name": "Renamed Org", "timezone": "Europe/Lisbon", "locale": "en"},
        )
        assert (
            ok.status_code == 200
            and ok.json()["name"] == "Renamed Org"
            and ok.json()["slug"] == "a"
        )
        assert (
            await c.patch(f"/api/v1/organizations/{b.organization_id}", json={"name": "Hijack"})
        ).status_code == 404
        assert (
            await c.patch(
                f"/api/v1/organizations/{a.organization_id}", json={"timezone": "Mars/Base"}
            )
        ).status_code == 422
        assert (
            await c.patch(f"/api/v1/organizations/{a.organization_id}", json={"slug": "new"})
        ).status_code == 422
        assert (
            await c.patch(
                f"/api/v1/organizations/{a.organization_id}", json={"status": "suspended"}
            )
        ).status_code == 422
    other = await rbac.get(Organization, b.organization_id)
    assert other is not None and other.name == "Org b"


@pytest.mark.asyncio
async def test_validation_errors_never_echo_submitted_secrets_nor_crash(rbac: AsyncSession):
    admin = await _tenant(rbac, "a")
    secret = "Short-Pw-1"  # 10 chars: fails the minimum length at the schema level
    async with _Client(rbac, admin) as c:
        weak = await c.post(
            "/api/v1/users",
            json={"name": "X Y", "email": "x@a.example.com", "password": secret, "role": "Auditor"},
        )
        assert weak.status_code == 422
        assert secret not in weak.text
        policy = await c.post(
            "/api/v1/users",
            json={
                "name": "X Y",
                "email": "x@a.example.com",
                "password": "aaaaaaaaaaaaaaaa",
                "role": "Auditor",
            },
        )
        assert policy.status_code == 422 and "aaaaaaaaaaaaaaaa" not in policy.text
        assert policy.json()["error"]["code"] == "VALIDATION_ERROR"
        assert any("assword" in d["msg"] for d in policy.json()["error"]["details"])
