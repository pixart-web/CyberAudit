from pathlib import Path

import httpx
import pytest

from cyberaudit import main
from cyberaudit.config import Settings
from cyberaudit.desktop_security import (
    DesktopSessionConfigurationError,
    desktop_request_authorized,
    load_desktop_session_secret,
)


def desktop_settings(secret_file: Path) -> Settings:
    return Settings(
        environment="desktop",
        desktop_mode=True,
        desktop_session_secret_file=secret_file,
        app_origin="http://127.0.0.1:32100",
        allowed_hosts=["127.0.0.1", "localhost"],
        database_url="postgresql+asyncpg://runtime:db-secret@127.0.0.1:55432/cyberaudit",
        redis_url="redis://:broker-secret@127.0.0.1:56379/0",
        jwt_secret="j" * 48,
        encryption_key="e" * 48,
        api_docs_enabled=False,
        rls_required=True,
        database_runtime_role="cyberaudit_runtime",
    )


def write_secret(path: Path, value: str = "a" * 64) -> None:
    path.write_text(value, encoding="ascii")
    path.chmod(0o600)


def test_desktop_mode_requires_private_session_file(tmp_path: Path):
    secret_file = tmp_path / "desktop-session"
    write_secret(secret_file)
    settings = desktop_settings(secret_file)

    assert desktop_request_authorized(settings, "/health", None)
    assert desktop_request_authorized(settings, "/ready", None)
    assert not desktop_request_authorized(settings, "/api/v1/users", None)
    assert not desktop_request_authorized(settings, "/api/v1/users", "wrong")
    assert desktop_request_authorized(settings, "/api/v1/users", "a" * 64)


def test_desktop_mode_rejects_development_defaults(tmp_path: Path):
    secret_file = tmp_path / "desktop-session"
    write_secret(secret_file)

    with pytest.raises(ValueError, match="Unsafe desktop configuration"):
        Settings(
            desktop_mode=True,
            desktop_session_secret_file=secret_file,
            app_origin="http://127.0.0.1:32100",
        )


def test_desktop_secret_rejects_unsafe_permissions(tmp_path: Path):
    secret_file = tmp_path / "desktop-session"
    write_secret(secret_file)
    secret_file.chmod(0o644)

    with pytest.raises(DesktopSessionConfigurationError):
        load_desktop_session_secret(secret_file)


def test_desktop_configuration_requires_loopback_origin(tmp_path: Path):
    secret_file = tmp_path / "desktop-session"
    write_secret(secret_file)

    with pytest.raises(ValueError, match="HTTP loopback APP_ORIGIN"):
        Settings(
            environment="desktop",
            desktop_mode=True,
            desktop_session_secret_file=secret_file,
            app_origin="https://portal.example.invalid",
            allowed_hosts=["127.0.0.1", "localhost"],
            database_url="postgresql+asyncpg://runtime:db-secret@127.0.0.1:55432/cyberaudit",
            redis_url="redis://:broker-secret@127.0.0.1:56379/0",
            jwt_secret="j" * 48,
            encryption_key="e" * 48,
            api_docs_enabled=False,
            rls_required=True,
            database_runtime_role="cyberaudit_runtime",
        )

    with pytest.raises(ValueError, match="HTTP loopback APP_ORIGIN"):
        Settings(
            environment="desktop",
            desktop_mode=True,
            desktop_session_secret_file=secret_file,
            app_origin="https://127.0.0.1:32100",
            allowed_hosts=["127.0.0.1", "localhost"],
            database_url="postgresql+asyncpg://runtime:db-secret@127.0.0.1:55432/cyberaudit",
            redis_url="redis://:broker-secret@127.0.0.1:56379/0",
            jwt_secret="j" * 48,
            encryption_key="e" * 48,
            api_docs_enabled=False,
            rls_required=True,
            database_runtime_role="cyberaudit_runtime",
        )


def test_server_mode_is_unchanged():
    settings = Settings(desktop_mode=False)
    assert desktop_request_authorized(settings, "/api/v1/users", None)


@pytest.mark.asyncio
async def test_desktop_middleware_enforces_session_capability(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    secret_file = tmp_path / "desktop-session"
    write_secret(secret_file)
    monkeypatch.setattr(main, "settings", desktop_settings(secret_file))
    transport = httpx.ASGITransport(app=main.app, raise_app_exceptions=False)

    async with httpx.AsyncClient(transport=transport, base_url="http://localhost") as client:
        rejected = await client.get("/metrics")
        accepted = await client.get(
            "/metrics",
            headers={"x-cyberaudit-desktop-session": "a" * 64},
        )

    assert rejected.status_code == 403
    assert rejected.json()["error"]["code"] == "DESKTOP_SESSION_REQUIRED"
    assert accepted.status_code == 200
    assert accepted.headers["content-type"].startswith("text/plain")
