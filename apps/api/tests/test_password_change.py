"""Forced password change and self-service change, using real JWT login."""

from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cyberaudit import admin_api
from cyberaudit.admin_api import ensure_rbac
from cyberaudit.db import get_db
from cyberaudit.main import app
from cyberaudit.models import AuditLog, Organization, Role, User
from cyberaudit.security import hash_password

OLD = "Temporary-Password-1!"
NEW = "A-Much-Better-Passphrase-42"


@pytest.fixture(autouse=True)
def _no_shared_redis_limiter(monkeypatch: pytest.MonkeyPatch) -> None:
    # The limiter counts in a shared Redis across test runs; its own behaviour is tested elsewhere.
    async def allow(*_args: object, **_kwargs: object) -> None:
        return None

    monkeypatch.setattr(admin_api, "enforce_rate_limit", allow)


async def _user(db: AsyncSession, must_change: bool) -> User:
    await ensure_rbac(db)
    org = Organization(name="O", slug="o-pw")
    db.add(org)
    await db.flush()
    role = await db.scalar(select(Role).where(Role.name == "Administrator"))
    user = User(
        organization_id=org.id,
        name="U",
        email="pw@o.example.com",
        password_hash=hash_password(OLD),
        must_change_password=must_change,
        roles=[role],
    )
    db.add(user)
    await db.commit()
    return user


class _Api:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def __aenter__(self) -> httpx.AsyncClient:
        async def override_db() -> AsyncIterator[AsyncSession]:
            yield self.db

        app.dependency_overrides[get_db] = override_db
        self.client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
            base_url="http://testserver",
        )
        return self.client

    async def __aexit__(self, *exc: object) -> None:
        await self.client.aclose()
        app.dependency_overrides.clear()


async def _login(c: httpx.AsyncClient, password: str) -> httpx.Response:
    return await c.post(
        "/api/v1/auth/login", json={"email": "pw@o.example.com", "password": password}
    )


@pytest.mark.asyncio
async def test_forced_change_blocks_everything_but_the_change_flow(db: AsyncSession):
    await _user(db, must_change=True)
    async with _Api(db) as c:
        token = (await _login(c, OLD)).json()["access_token"]
        h = {"Authorization": f"Bearer {token}"}
        me = await c.get("/api/v1/auth/me", headers=h)
        assert me.status_code == 200 and me.json()["must_change_password"] is True
        blocked = await c.get("/api/v1/users", headers=h)
        assert blocked.status_code == 403 and "PASSWORD_CHANGE_REQUIRED" in blocked.text
        assert (await c.get("/api/v1/clients", headers=h)).status_code == 403

        bad = await c.post(
            "/api/v1/auth/change-password",
            headers=h,
            json={"current_password": "wrong-password", "new_password": NEW},
        )
        assert bad.status_code == 401
        same = await c.post(
            "/api/v1/auth/change-password",
            headers=h,
            json={"current_password": OLD, "new_password": OLD},
        )
        assert same.status_code == 422
        weak = await c.post(
            "/api/v1/auth/change-password",
            headers=h,
            json={"current_password": OLD, "new_password": "aaaaaaaaaaaaaaaa"},
        )
        assert weak.status_code == 422

        ok = await c.post(
            "/api/v1/auth/change-password",
            headers=h,
            json={"current_password": OLD, "new_password": NEW},
        )
        assert ok.status_code == 204
        assert (
            await c.get("/api/v1/users", headers=h)
        ).status_code == 200  # gate lifted immediately
        assert (await _login(c, OLD)).status_code == 401
        assert (await _login(c, NEW)).status_code == 200

    user = (await db.scalars(select(User))).one()
    await db.refresh(user)
    assert user.must_change_password is False
    actions = {a for (a,) in (await db.execute(select(AuditLog.action))).all()}
    assert {"auth.password_changed", "auth.password_change_failed"} <= actions


@pytest.mark.asyncio
async def test_admin_created_users_must_change_their_password(db: AsyncSession):
    await _user(db, must_change=False)
    async with _Api(db) as c:
        h = {"Authorization": f"Bearer {(await _login(c, OLD)).json()['access_token']}"}
        created = await c.post(
            "/api/v1/users",
            headers=h,
            json={
                "name": "New Hire",
                "email": "hire@o.example.com",
                "password": "Initial-Password-77!",
                "role": "Auditor",
            },
        )
        assert created.status_code == 201 and created.json()["must_change_password"] is True
        hire = await c.post(
            "/api/v1/auth/login",
            json={"email": "hire@o.example.com", "password": "Initial-Password-77!"},
        )
        gate = await c.get(
            "/api/v1/clients", headers={"Authorization": f"Bearer {hire.json()['access_token']}"}
        )
        assert gate.status_code == 403
