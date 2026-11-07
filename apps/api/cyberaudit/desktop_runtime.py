"""Closed entrypoints used by the packaged CyberAudit desktop sidecars.

The native supervisor controls the environment and may select only the fixed
operations exposed here. No command, module path, bind address, or filesystem
path is accepted from the web frontend.
"""

from __future__ import annotations

import argparse
import ipaddress
import multiprocessing
import os
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


def run_worker() -> int:
    from dramatiq.cli import main as dramatiq_main

    desktop_settings()
    multiprocessing.freeze_support()
    return int(dramatiq_main(worker_arguments()) or 0)


def api_main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cyberaudit-api", allow_abbrev=False)
    parser.add_argument("operation", choices=("serve", "migrate"))
    arguments = parser.parse_args(argv)
    if arguments.operation == "migrate":
        run_migrations()
        return 0
    run_api()


def worker_main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cyberaudit-worker", allow_abbrev=False)
    parser.parse_args(argv)
    return run_worker()


def guarded_entrypoint(function: Callable[[], int | None]) -> int:
    try:
        return int(function() or 0)
    except DesktopRuntimeConfigurationError as exc:
        print(f"CyberAudit desktop configuration error: {exc}", file=sys.stderr)
        return CONFIGURATION_EXIT_CODE
