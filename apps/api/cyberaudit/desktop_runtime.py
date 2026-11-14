"""Closed entrypoints used by the packaged CyberAudit desktop sidecars.

The native supervisor controls the environment and may select only the fixed
operations exposed here. No command, module path, bind address, or filesystem
path is accepted from the web frontend.
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import multiprocessing
import os
import stat
import sys
from argparse import Namespace
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any, NoReturn

from alembic.config import Config
from pydantic import ValidationError


class DesktopRuntimeConfigurationError(RuntimeError):
    """The native supervisor supplied an unsafe runtime configuration."""


CONFIGURATION_EXIT_CODE = 78


def desktop_settings() -> Any:
    from cyberaudit.config import get_settings

    try:
        settings = get_settings()
    except ValidationError as exc:
        raise DesktopRuntimeConfigurationError("desktop settings were rejected") from exc
    if not settings.desktop_mode:
        raise DesktopRuntimeConfigurationError("DESKTOP_MODE must be enabled")
    return settings


def _bounded_integer(name: str, default: int, *, minimum: int, maximum: int) -> int:
    raw = os.environ.get(name, str(default))
    try:
        value = int(raw)
    except ValueError as exc:
        raise DesktopRuntimeConfigurationError(f"{name} must be an integer") from exc
    if not minimum <= value <= maximum:
        raise DesktopRuntimeConfigurationError(f"{name} must be between {minimum} and {maximum}")
    return value


def api_bind() -> tuple[str, int]:
    host = os.environ.get("CYBERAUDIT_DESKTOP_API_HOST", "127.0.0.1")
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise DesktopRuntimeConfigurationError(
            "CYBERAUDIT_DESKTOP_API_HOST must be a loopback IP address"
        ) from exc
    if not address.is_loopback:
        raise DesktopRuntimeConfigurationError("desktop API may bind only to loopback")
    port = _bounded_integer("CYBERAUDIT_DESKTOP_API_PORT", 48123, minimum=1024, maximum=65535)
    return host, port


def runtime_resource_root() -> Path:
    """Locate immutable Alembic resources in source and PyInstaller bundles."""

    return Path(__file__).resolve().parent.parent


def alembic_configuration() -> Config:
    root = runtime_resource_root()
    ini = root / "alembic.ini"
    scripts = root / "alembic"
    if not ini.is_file() or not scripts.is_dir():
        raise DesktopRuntimeConfigurationError("packaged Alembic resources are missing")
    configuration = Config(str(ini))
    configuration.set_main_option("script_location", str(scripts))
    return configuration


def run_migrations() -> None:
    from alembic import command

    # Importing Settings performs the fail-closed desktop configuration checks
    # before a database connection is attempted.
    desktop_settings()
    command.upgrade(alembic_configuration(), "head")
    asyncio.run(provision_rbac_catalog())


async def provision_rbac_catalog() -> None:
    """Reconcile fixed RBAC data using the migration owner's connection."""

    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from sqlalchemy.pool import NullPool

    from cyberaudit.provisioning import provision_builtin_adapters
    from cyberaudit.rbac_provisioning import ensure_rbac

    settings = desktop_settings()
    engine = create_async_engine(
        settings.database_url,
        poolclass=NullPool,
        connect_args={
            "server_settings": {
                "application_name": "cyberaudit-desktop-migration",
                "statement_timeout": str(settings.database_statement_timeout_ms),
            }
        },
    )
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with sessions() as session:
            await ensure_rbac(session)
            await provision_builtin_adapters(session)
            await session.commit()
    finally:
        await engine.dispose()


def run_api() -> NoReturn:
    import uvicorn

    desktop_settings()
    host, port = api_bind()
    uvicorn.run(
        "cyberaudit.main:app",
        host=host,
        port=port,
        access_log=False,
        log_level="info",
        proxy_headers=False,
        server_header=False,
    )
    raise SystemExit(0)


def worker_arguments() -> Namespace:
    from dramatiq.cli import make_argument_parser

    threads = _bounded_integer("CYBERAUDIT_DESKTOP_WORKER_THREADS", 2, minimum=1, maximum=8)
    arguments = make_argument_parser().parse_args(
        [
            "cyberaudit.worker",
            "--processes",
            "1",
            "--threads",
            str(threads),
            "--use-spawn",
        ]
    )
    return arguments


def verify_worker_package() -> None:
    """Fail closed when required Dramatiq broker resources were not bundled."""

    from dramatiq.brokers.redis import _scripts

    required_scripts = {"dispatch", "maxstack"}
    missing = sorted(required_scripts.difference(_scripts))
    if missing:
        raise DesktopRuntimeConfigurationError(
            f"packaged worker broker resources are missing: {', '.join(missing)}"
        )


def run_worker() -> int:
    from dramatiq.cli import main as dramatiq_main

    settings = desktop_settings()
    ready_file = _provision_worker_readiness(settings)
    try:
        return int(dramatiq_main(worker_arguments()) or 0)
    finally:
        try:
            ready_file.unlink()
        except FileNotFoundError:
            pass


def _provision_worker_readiness(settings: Any) -> Path:
    raw = os.environ.get("CYBERAUDIT_DESKTOP_READY_FILE")
    if not raw:
        raise DesktopRuntimeConfigurationError("CYBERAUDIT_DESKTOP_READY_FILE is required")
    path = Path(raw)
    session_file = settings.desktop_session_secret_file
    if session_file is None or path.parent != session_file.parent or path.name != "worker-ready":
        raise DesktopRuntimeConfigurationError("worker readiness path is outside configuration")
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError as exc:
        raise DesktopRuntimeConfigurationError(
            "worker readiness file could not be created"
        ) from exc
    try:
        os.write(descriptor, b"ready\n")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    if os.name == "posix" and stat.S_IMODE(path.stat().st_mode) & 0o077:
        path.unlink(missing_ok=True)
        raise DesktopRuntimeConfigurationError("worker readiness file permissions are unsafe")
    return path


def api_main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cyberaudit-api", allow_abbrev=False)
    parser.add_argument("operation", choices=("serve", "migrate"))
    arguments = parser.parse_args(argv)
    if arguments.operation == "migrate":
        run_migrations()
        return 0
    run_api()


def worker_main(argv: Sequence[str] | None = None) -> int:
    # PyInstaller multiprocessing children re-enter this executable with private
    # interpreter arguments. Intercept those before our closed CLI parser.
    multiprocessing.freeze_support()
    parser = argparse.ArgumentParser(prog="cyberaudit-worker", allow_abbrev=False)
    parser.add_argument("--verify-package", action="store_true")
    arguments = parser.parse_args(argv)
    if arguments.verify_package:
        verify_worker_package()
        return 0
    return run_worker()


def guarded_entrypoint(function: Callable[[], int | None]) -> int:
    try:
        return int(function() or 0)
    except DesktopRuntimeConfigurationError as exc:
        print(f"CyberAudit desktop configuration error: {exc}", file=sys.stderr)
        return CONFIGURATION_EXIT_CODE
