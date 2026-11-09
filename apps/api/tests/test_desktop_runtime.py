from pathlib import Path
from types import SimpleNamespace

import pytest

from cyberaudit import desktop_runtime


def test_api_bind_is_loopback_only(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CYBERAUDIT_DESKTOP_API_HOST", "0.0.0.0")  # noqa: S104
    with pytest.raises(
        desktop_runtime.DesktopRuntimeConfigurationError,
        match="only to loopback",
    ):
        desktop_runtime.api_bind()


def test_api_bind_validates_port(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CYBERAUDIT_DESKTOP_API_HOST", "::1")
    monkeypatch.setenv("CYBERAUDIT_DESKTOP_API_PORT", "48123")
    assert desktop_runtime.api_bind() == ("::1", 48123)

    monkeypatch.setenv("CYBERAUDIT_DESKTOP_API_PORT", "80")
    with pytest.raises(desktop_runtime.DesktopRuntimeConfigurationError):
        desktop_runtime.api_bind()


def test_packaged_migration_resources_are_resolved() -> None:
    configuration = desktop_runtime.alembic_configuration()
    assert Path(configuration.config_file_name).name == "alembic.ini"
    assert Path(configuration.get_main_option("script_location")).name == "alembic"


def test_worker_configuration_is_fixed_and_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CYBERAUDIT_DESKTOP_WORKER_THREADS", "4")
    arguments = desktop_runtime.worker_arguments()
    assert arguments.broker == "cyberaudit.worker"
    assert arguments.processes == 1
    assert arguments.threads == 4
    assert arguments.use_spawn is True

    monkeypatch.setenv("CYBERAUDIT_DESKTOP_WORKER_THREADS", "64")
    with pytest.raises(desktop_runtime.DesktopRuntimeConfigurationError):
        desktop_runtime.worker_arguments()


def test_worker_readiness_capability_is_private_and_scoped(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    configuration = tmp_path / "configuration"
    configuration.mkdir()
    session = configuration / "desktop-session"
    session.write_text("a" * 64, encoding="ascii")
    readiness = configuration / "worker-ready"
    monkeypatch.setenv("CYBERAUDIT_DESKTOP_READY_FILE", str(readiness))

    created = desktop_runtime._provision_worker_readiness(  # noqa: SLF001
        SimpleNamespace(desktop_session_secret_file=session)
    )

    assert created == readiness
    assert readiness.read_text(encoding="ascii") == "ready\n"
    assert readiness.stat().st_mode & 0o077 == 0
    readiness.unlink()

    monkeypatch.setenv("CYBERAUDIT_DESKTOP_READY_FILE", str(tmp_path / "worker-ready"))
    with pytest.raises(
        desktop_runtime.DesktopRuntimeConfigurationError,
        match="outside configuration",
    ):
        desktop_runtime._provision_worker_readiness(  # noqa: SLF001
            SimpleNamespace(desktop_session_secret_file=session)
        )


def test_api_entrypoint_exposes_only_fixed_operations(monkeypatch: pytest.MonkeyPatch) -> None:
    called: list[str] = []
    monkeypatch.setattr(desktop_runtime, "run_migrations", lambda: called.append("migrate"))
    assert desktop_runtime.api_main(["migrate"]) == 0
    assert called == ["migrate"]

    with pytest.raises(SystemExit):
        desktop_runtime.api_main(["arbitrary-command"])


def test_guarded_entrypoint_sanitizes_invalid_settings(
    capsys: pytest.CaptureFixture[str],
) -> None:
    def rejected() -> int:
        raise desktop_runtime.DesktopRuntimeConfigurationError("settings rejected")

    assert desktop_runtime.guarded_entrypoint(rejected) == 78
    assert capsys.readouterr().err == (
        "CyberAudit desktop configuration error: settings rejected\n"
    )
