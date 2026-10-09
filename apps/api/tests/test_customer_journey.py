"""End-to-end customer journey through the real HTTP routes with real JWT login.

bootstrap -> login -> user (forced password change) -> client -> engagement -> scope/target ->
signed authorization PDF -> activation -> asset -> import -> findings -> report -> PDF ->
audit trail -> second tenant isolation. No mocked handlers; only the Redis rate limiter and the
upload directory are redirected for hermetic CI.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cyberaudit import admin_api
from cyberaudit import main as main_module
from cyberaudit import storage as storage_module
from cyberaudit.db import get_db
from cyberaudit.main import app
from cyberaudit.models import AuditLog

TOKEN = "journey-bootstrap-token-0123456789"
PASSWORD = "Journey-Admin-Passphrase-1!"
PDF = b"%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF"
CSV = (
    b"title,severity,category,description,affected_component,source_identifier\n"
    b"Exposed admin interface,high,network,Management reachable from user VLAN,core-fw-01,J-1\n"
    b"Legacy TLS 1.0 enabled,medium,tls,Deprecated protocol,vpn-gw-02,J-2\n"
)


@pytest.mark.asyncio
async def test_full_customer_journey_and_tenant_isolation(
    db: AsyncSession, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    async def no_limit(*_a: object, **_k: object) -> None:
        return None

    monkeypatch.setattr(main_module, "enforce_rate_limit", no_limit)
    monkeypatch.setattr(admin_api, "enforce_rate_limit", no_limit)
    monkeypatch.setattr(
        storage_module,
        "get_settings",
        lambda: SimpleNamespace(upload_dir=tmp_path, max_upload_bytes=5_000_000),
    )
    monkeypatch.setattr(
        admin_api,
        "get_settings",
        lambda: SimpleNamespace(bootstrap_token=TOKEN, license_trusted_public_keys=[]),
    )

    async def override_db() -> AsyncIterator[AsyncSession]:
        yield db

    app.dependency_overrides[get_db] = override_db
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
            base_url="http://testserver",
        ) as c:

            def auth(token: str) -> dict[str, str]:
                return {"Authorization": f"Bearer {token}"}

            async def login(email: str, password: str) -> str:
                r = await c.post("/api/v1/auth/login", json={"email": email, "password": password})
                assert r.status_code == 200, r.text
                return r.json()["access_token"]

            # 1. First-run bootstrap (one-shot).
            body = {
                "name": "Pixart",
                "slug": "pixart",
                "admin_name": "Root",
                "admin_email": "root@pixart.example.com",
                "admin_password": PASSWORD,
                "bootstrap_token": TOKEN,
            }
            assert (await c.post("/api/v1/setup/initialize", json=body)).status_code == 201
            assert (await c.post("/api/v1/setup/initialize", json=body)).status_code == 403

            # 2. Login, create a user who must change password, who then acts under RBAC.
            admin = await login("root@pixart.example.com", PASSWORD)
            made = await c.post(
                "/api/v1/users",
                headers=auth(admin),
                json={
                    "name": "Maria",
                    "email": "maria@pixart.example.com",
                    "password": "Initial-Passphrase-77!",
                    "role": "Security Analyst",
                },
            )
            assert made.status_code == 201
            maria0 = await login("maria@pixart.example.com", "Initial-Passphrase-77!")
            assert (await c.get("/api/v1/clients", headers=auth(maria0))).status_code == 403
            assert (
                await c.post(
                    "/api/v1/auth/change-password",
                    headers=auth(maria0),
                    json={
                        "current_password": "Initial-Passphrase-77!",
                        "new_password": "Own-Secret-Passphrase-88!",
                    },
                )
            ).status_code == 204
            maria = await login("maria@pixart.example.com", "Own-Secret-Passphrase-88!")
            assert (
                await c.get("/api/v1/users", headers=auth(maria))
            ).status_code == 403  # analysts cannot administer

            # 3. Business objects (as the administrator).
            client = (
                await c.post(
                    "/api/v1/clients", headers=auth(admin), json={"name": "Northstar Industries"}
                )
            ).json()
            me = (await c.get("/api/v1/auth/me", headers=auth(admin))).json()
            eng = await c.post(
                "/api/v1/engagements",
                headers=auth(admin),
                json={
                    "client_id": client["id"],
                    "name": "Assessment",
                    "code": "NS-1",
                    "mode": "client",
                    "owner_id": me["id"],
                    "risk_level": "high",
                    "start_date": "2026-10-01",
                    "end_date": "2026-12-01",
                },
            )
            assert eng.status_code == 201, eng.text
            eid = eng.json()["id"]
            scope = (
                await c.post(
                    "/api/v1/scopes",
                    headers=auth(admin),
                    json={"engagement_id": eid, "name": "Core"},
                )
            ).json()
            tgt = await c.post(
                "/api/v1/scope-targets",
                headers=auth(admin),
                json={
                    "scope_id": scope["id"],
                    "target_type": "cidr",
                    "target_value": "10.20.0.0/24",
                },
            )
            assert tgt.status_code == 201
            assert (
                await c.post(
                    "/api/v1/scope-targets",
                    headers=auth(admin),
                    json={"scope_id": scope["id"], "target_type": "ip", "target_value": "nope"},
                )
            ).status_code == 422

            # 4. Activation is refused without a valid authorization, accepted with one.
            for status in ("pending_authorization",):
                assert (
                    await c.patch(
                        f"/api/v1/engagements/{eid}/status",
                        headers=auth(admin),
                        json={"status": status},
                    )
                ).status_code == 200
            assert (
                await c.patch(
                    f"/api/v1/engagements/{eid}/status",
                    headers=auth(admin),
                    json={"status": "authorized"},
                )
            ).status_code in {409, 422}
            up = await c.post(
                "/api/v1/authorizations",
                headers=auth(admin),
                data={
                    "engagement_id": eid,
                    "valid_from": "2026-10-01",
                    "valid_until": "2026-12-31",
                    "signed_by": "CISO",
                },
                files={"file": ("auth.pdf", PDF, "application/pdf")},
            )
            assert up.status_code == 201, up.text
            for status in ("authorized", "active"):
                assert (
                    await c.patch(
                        f"/api/v1/engagements/{eid}/status",
                        headers=auth(admin),
                        json={"status": status},
                    )
                ).status_code == 200

            # 5. Assets, import, findings (analyst role: imports are an analyst capability).
            asset = await c.post(
                "/api/v1/assets",
                headers=auth(admin),
                json={
                    "engagement_id": eid,
                    "name": "core-fw-01",
                    "asset_type": "network_device",
                    "identifier": "core-fw-01",
                    "criticality": "high",
                },
            )
            assert asset.status_code == 201
            imp = await c.post(
                "/api/v1/imports",
                headers=auth(maria),
                data={"engagement_id": eid},
                files={"upload": ("results.csv", CSV, "text/csv")},
            )
            assert imp.status_code == 201, imp.text
            iid = imp.json()["id"]
            assert (
                await c.post(f"/api/v1/imports/{iid}/preview", headers=auth(maria))
            ).status_code == 200
            confirmed = await c.post(f"/api/v1/imports/{iid}/confirm", headers=auth(maria))
            assert confirmed.status_code == 200, confirmed.text
            assert confirmed.json()["findings_created"] == 2
            findings = (await c.get("/api/v1/findings", headers=auth(maria))).json()
            assert findings["total"] == 2 and all(
                f["verification_status"] == "unverified" for f in findings["items"]
            )

            # 6. Report + PDF export; notification for the import; audit trail.
            report = await c.post(
                f"/api/v1/engagements/{eid}/reports",
                headers=auth(admin),
                json={"report_type": "executive_summary", "include_ai_summary": False},
            )
            assert report.status_code == 201
            pdf = await c.get(
                f"/api/v1/reports/{report.json()['id']}/export.pdf", headers=auth(admin)
            )
            assert (
                pdf.status_code == 200
                and pdf.content.startswith(b"%PDF")
                and pdf.headers["cache-control"] == "no-store"
            )
            notes = (await c.get("/api/v1/notifications", headers=auth(maria))).json()["items"]
            assert any(n["event_type"] == "import.completed" for n in notes)
            dash = (await c.get("/api/v1/dashboard", headers=auth(admin))).json()
            assert (
                dash["metrics"]["findings"] == 2
                and dash["metrics"]["assets"] == 1
                and dash["metrics"]["posture"] is not None
            )

            # 7. Second tenant (platform admin) cannot see anything of the first.
            org = await c.post(
                "/api/v1/platform/organizations",
                headers=auth(admin),
                json={
                    "name": "Contoso",
                    "slug": "contoso",
                    "admin_name": "Eve",
                    "admin_email": "eve@contoso.example.com",
                    "admin_password": "Contoso-Passphrase-99!",
                },
            )
            assert org.status_code == 201, org.text
            eve0 = await login("eve@contoso.example.com", "Contoso-Passphrase-99!")
            assert (
                await c.post(
                    "/api/v1/auth/change-password",
                    headers=auth(eve0),
                    json={
                        "current_password": "Contoso-Passphrase-99!",
                        "new_password": "Contoso-New-Passphrase-1!",
                    },
                )
            ).status_code == 204
            eve = await login("eve@contoso.example.com", "Contoso-New-Passphrase-1!")
            assert (await c.get("/api/v1/findings", headers=auth(eve))).json()["total"] == 0
            assert (await c.get("/api/v1/clients", headers=auth(eve))).json()["total"] == 0
            assert (await c.get(f"/api/v1/engagements/{eid}", headers=auth(eve))).status_code == 404
            assert (
                await c.get(f"/api/v1/reports/{report.json()['id']}/export.pdf", headers=auth(eve))
            ).status_code == 404
            assert [
                u["email"]
                for u in (await c.get("/api/v1/users", headers=auth(eve))).json()["items"]
            ] == ["eve@contoso.example.com"]
    finally:
        app.dependency_overrides.clear()

    actions = {a for (a,) in (await db.execute(select(AuditLog.action))).all()}
    assert {
        "setup.initialized",
        "user.created",
        "auth.password_changed",
        "client.created",
        "engagement.created",
        "scope.created",
        "authorization.uploaded",
        "asset.created",
        "import.confirmed",
        "report.generated",
        "report.exported",
        "organization.created",
    } <= actions
