"""Manual evidence upload: private, hashed, tenant-scoped, labelled as manual."""

from __future__ import annotations

import hashlib
from collections.abc import AsyncIterator
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cyberaudit import storage as storage_module
from cyberaudit.admin_api import ensure_rbac
from cyberaudit.db import get_db
from cyberaudit.main import app
from cyberaudit.models import (
    AuditLog,
    Client,
    Engagement,
    EngagementMode,
    Evidence,
    Organization,
    Role,
    User,
)
from cyberaudit.security import current_user


async def _tenant(db: AsyncSession, slug: str, role: str) -> tuple[User, Engagement]:
    org = Organization(name=slug, slug=slug)
    db.add(org)
    await db.flush()
    r = await db.scalar(select(Role).where(Role.name == role))
    user = User(
        organization_id=org.id,
        name="U",
        email=f"u@{slug}.example.com",
        password_hash="not-a-real-hash",  # noqa: S106
        roles=[r],
    )
    client = Client(organization_id=org.id, name="C")
    db.add_all([user, client])
    await db.flush()
    eng = Engagement(
        organization_id=org.id,
        client_id=client.id,
        name="E",
        code=f"E-{slug}",
        mode=EngagementMode.CLIENT,
        owner_id=user.id,
    )
    db.add(eng)
    await db.commit()
    return user, eng


async def _post(
    db: AsyncSession, user: User, engagement_id: str, name: str, mime: str, content: bytes
):
    async def override_db() -> AsyncIterator[AsyncSession]:
        yield db

    async def override_user() -> User:
        return await db.get(User, user.id, populate_existing=True)  # type: ignore[return-value]

    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[current_user] = override_user
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
            base_url="http://testserver",
        ) as c:
            return await c.post(
                "/api/v1/evidence",
                data={"engagement_id": engagement_id, "title": "Firewall export"},
                files={"file": (name, content, mime)},
            )
    finally:
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_manual_upload_is_hashed_private_labelled_and_audited(
    db: AsyncSession, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setattr(
        storage_module,
        "get_settings",
        lambda: SimpleNamespace(upload_dir=tmp_path, max_upload_bytes=1_000_000),
    )
    await ensure_rbac(db)
    user, eng = await _tenant(db, "a", "Security Analyst")
    body = b"rule 1 allow any any\n"
    ok = await _post(db, user, eng.id, "fw.txt", "text/plain", body)
    assert ok.status_code == 201, ok.text
    data = ok.json()
    assert data["content_hash"] == hashlib.sha256(body).hexdigest()
    assert data["collected_by_adapter"] == "manual_upload" and data["sensitivity"] == "confidential"
    row = await db.get(Evidence, data["id"])
    assert row is not None and row.job_id is None and row.evidence_metadata["manual"] is True
    stored = tmp_path / str(row.storage_key)
    assert stored.read_bytes() == body and (stored.stat().st_mode & 0o077) == 0
    assert "evidence.uploaded" in {a for (a,) in (await db.execute(select(AuditLog.action))).all()}


@pytest.mark.asyncio
async def test_manual_upload_rejects_bad_type_foreign_engagement_and_unauthorized_role(
    db: AsyncSession, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setattr(
        storage_module,
        "get_settings",
        lambda: SimpleNamespace(upload_dir=tmp_path, max_upload_bytes=1_000_000),
    )
    await ensure_rbac(db)
    analyst_a, eng_a = await _tenant(db, "a", "Security Analyst")
    _, eng_b = await _tenant(db, "b", "Security Analyst")
    viewer, eng_v = await _tenant(db, "v", "Read-only Viewer")
    assert (
        await _post(db, analyst_a, eng_a.id, "x.exe", "application/octet-stream", b"MZ")
    ).status_code == 422
    assert (
        await _post(db, analyst_a, eng_a.id, "x.txt", "application/x-evil", b"hi")
    ).status_code == 422
    assert (await _post(db, analyst_a, eng_b.id, "x.txt", "text/plain", b"hi")).status_code == 404
    assert (await _post(db, viewer, eng_v.id, "x.txt", "text/plain", b"hi")).status_code == 403
    assert list(tmp_path.iterdir()) == []
