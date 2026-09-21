from __future__ import annotations

import hashlib
from io import BytesIO

import jwt
import pytest
from fastapi import HTTPException, UploadFile
from fastapi.security import HTTPAuthorizationCredentials
from starlette.datastructures import Headers
from starlette.requests import Request

from cyberaudit.config import Settings
from cyberaudit.models import Organization, RefreshToken, User
from cyberaudit.rate_limit import enforce_rate_limit
from cyberaudit.security import (
    create_access_token,
    create_step_up_token,
    current_user,
    decode_token,
    hash_password,
    issue_refresh_token,
    verify_password,
)
from cyberaudit.storage import LocalStorage


def _upload(filename: str, mime_type: str, content: bytes) -> UploadFile:
    return UploadFile(
        file=BytesIO(content),
        filename=filename,
        headers=Headers({"content-type": mime_type}),
    )


class FakeRateLimitRedis:
    def __init__(self, count: int) -> None:
        self.count = count
        self.closed = False

    def pipeline(self, *, transaction: bool):
        assert transaction is True
        return self

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_: object) -> None:
        return None

    def incr(self, key: str):
        assert key.startswith("cyberaudit:rate:login:")
        return self

    def expire(self, key: str, seconds: int, *, nx: bool):
        assert key.startswith("cyberaudit:rate:login:")
        assert seconds == 60
        assert nx is True
        return self

    async def execute(self) -> list[int | bool]:
        return [self.count, True]

    async def aclose(self) -> None:
        self.closed = True


@pytest.mark.asyncio
async def test_distributed_rate_limit_accepts_then_rejects(monkeypatch) -> None:
    settings = Settings(environment="test")
    monkeypatch.setattr("cyberaudit.rate_limit.get_settings", lambda: settings)
    request = Request({"type": "http", "client": ("127.0.0.1", 54321), "headers": []})

    accepted = FakeRateLimitRedis(count=10)
    monkeypatch.setattr("cyberaudit.rate_limit.redis.from_url", lambda *_args, **_kwargs: accepted)
    await enforce_rate_limit(request, category="login", limit=10, window_seconds=60)
    assert accepted.closed is True

    rejected = FakeRateLimitRedis(count=11)
    monkeypatch.setattr("cyberaudit.rate_limit.redis.from_url", lambda *_args, **_kwargs: rejected)
    with pytest.raises(HTTPException) as limited:
        await enforce_rate_limit(request, category="login", limit=10, window_seconds=60)
    assert limited.value.status_code == 429
    assert rejected.closed is True


@pytest.mark.asyncio
async def test_local_storage_validates_and_protects_private_files(tmp_path, monkeypatch) -> None:
    settings = Settings(
        environment="test",
        upload_dir=tmp_path / "private-uploads",
        max_upload_bytes=32,
    )
    monkeypatch.setattr("cyberaudit.storage.get_settings", lambda: settings)
    storage = LocalStorage()
    pdf = b"%PDF-1.7\nsynthetic"

    key, digest, size = await storage.save_pdf(_upload("authorization.pdf", "application/pdf", pdf))
    assert key.endswith(".pdf")
    assert digest == hashlib.sha256(pdf).hexdigest()
    assert size == len(pdf)
    assert storage.read_private_file(key, 32) == pdf

    with pytest.raises(ValueError, match="Only PDF"):
        await storage.save_pdf(_upload("../authorization.txt", "application/pdf", pdf))
    with pytest.raises(ValueError, match="MIME"):
        await storage.save_pdf(_upload("authorization.pdf", "text/plain", pdf))
    with pytest.raises(ValueError, match="signature"):
        await storage.save_pdf(_upload("authorization.pdf", "application/pdf", b"not-a-pdf"))
    with pytest.raises(ValueError, match="too large"):
        await storage.save_pdf(
            _upload("authorization.pdf", "application/pdf", b"%PDF-" + b"x" * 40)
        )

    private_key, _, _ = await storage.save_private_file(
        _upload("evidence.json", "application/json", b'{"simulated":true}'),
        allowed_extensions={".json"},
        allowed_mime_types={"application/json"},
        maximum_bytes=64,
    )
    assert storage.read_private_file(private_key, 64) == b'{"simulated":true}'
    with pytest.raises(ValueError, match="extension"):
        await storage.save_private_file(
            _upload("evidence.html", "application/json", b"safe"),
            allowed_extensions={".json"},
            allowed_mime_types={"application/json"},
            maximum_bytes=64,
        )
    with pytest.raises(ValueError, match="MIME"):
        await storage.save_private_file(
            _upload("evidence.json", "text/html", b"safe"),
            allowed_extensions={".json"},
            allowed_mime_types={"application/json"},
            maximum_bytes=64,
        )
    with pytest.raises(ValueError, match="empty"):
        await storage.save_private_file(
            _upload("evidence.json", "application/json", b""),
            allowed_extensions={".json"},
            allowed_mime_types={"application/json"},
            maximum_bytes=64,
        )
    with pytest.raises(ValueError, match="Unsafe storage key"):
        storage.read_private_file("../outside", 64)
    with pytest.raises(ValueError, match="not found"):
        storage.read_private_file("missing.json", 64)
    with pytest.raises(ValueError, match="maximum size"):
        storage.read_private_file(private_key, 2)


@pytest.mark.asyncio
async def test_password_tokens_refresh_and_authenticated_user_contract(db) -> None:
    organization = Organization(name="Security Tenant", slug="security-tenant")
    db.add(organization)
    await db.flush()
    user = User(
        organization_id=organization.id,
        name="Security Operator",
        email="security-operator@example.com",
        password_hash=hash_password("A-Unique-Security-Password-2026!"),
        status="active",
    )
    db.add(user)
    await db.flush()

    assert verify_password("A-Unique-Security-Password-2026!", user.password_hash)
    assert not verify_password("incorrect", user.password_hash)
    assert not verify_password("incorrect", "invalid-hash")

    access_token = create_access_token(user)
    claims = decode_token(access_token)
    assert claims["sub"] == user.id
    assert claims["org"] == organization.id
    with pytest.raises(ValueError, match="phishing resistant"):
        create_step_up_token(user, "totp")
    step_up = create_step_up_token(user, "webauthn")
    assert decode_token(step_up, expected_type="step_up")["amr"] == ["webauthn"]
    with pytest.raises(HTTPException) as wrong_type:
        decode_token(access_token, expected_type="step_up")
    assert wrong_type.value.status_code == 401
    with pytest.raises(HTTPException):
        decode_token("not-a-token")

    refresh = await issue_refresh_token(db, user)
    token_id, raw = refresh.split(".", 1)
    stored = await db.get(RefreshToken, token_id)
    assert stored is not None
    assert stored.token_hash == hashlib.sha256(raw.encode()).hexdigest()

    credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=access_token)
    authenticated = await current_user(credentials, db)
    assert authenticated.id == user.id
    with pytest.raises(HTTPException) as missing:
        await current_user(None, db)
    assert missing.value.status_code == 401

    forged = jwt.encode(
        {"sub": user.id, "org": organization.id, "type": "refresh"},
        Settings().jwt_secret,
        algorithm="HS256",
    )
    with pytest.raises(HTTPException):
        await current_user(
            HTTPAuthorizationCredentials(scheme="Bearer", credentials=forged),
            db,
        )
    missing_tenant = jwt.encode(
        {"sub": user.id, "type": "access"},
        Settings().jwt_secret,
        algorithm="HS256",
    )
    with pytest.raises(HTTPException) as missing_tenant_error:
        await current_user(
            HTTPAuthorizationCredentials(scheme="Bearer", credentials=missing_tenant),
            db,
        )
    assert missing_tenant_error.value.status_code == 401
    invalid_tenant = jwt.encode(
        {"sub": user.id, "org": "frontend-controlled", "type": "access"},
        Settings().jwt_secret,
        algorithm="HS256",
    )
    with pytest.raises(HTTPException) as invalid_tenant_error:
        await current_user(
            HTTPAuthorizationCredentials(scheme="Bearer", credentials=invalid_tenant),
            db,
        )
    assert invalid_tenant_error.value.status_code == 401
