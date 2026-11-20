"""Trust boundary between the native desktop runtime and the local API."""

from __future__ import annotations

import hmac
import os
import stat
from pathlib import Path

from cyberaudit.config import Settings

DESKTOP_SESSION_HEADER = "x-cyberaudit-desktop-session"
DESKTOP_PUBLIC_PATHS = frozenset({"/health", "/ready"})


class DesktopSessionConfigurationError(RuntimeError):
    """The native runtime supplied an unsafe or unreadable session capability."""


def load_desktop_session_secret(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise DesktopSessionConfigurationError("Desktop session secret must be a regular file")
    if os.name == "posix":
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & 0o077:
            raise DesktopSessionConfigurationError(
                "Desktop session secret must not be accessible by group or other users"
            )
    secret = path.read_text(encoding="ascii").strip()
    if len(secret) < 32 or any(character.isspace() for character in secret):
        raise DesktopSessionConfigurationError("Desktop session secret is malformed")
    return secret


def desktop_request_authorized(settings: Settings, path: str, presented: str | None) -> bool:
    if not settings.desktop_mode or path in DESKTOP_PUBLIC_PATHS:
        return True
    secret_file = settings.desktop_session_secret_file
    if secret_file is None or presented is None:
        return False
    try:
        expected = load_desktop_session_secret(secret_file)
    except (DesktopSessionConfigurationError, OSError, UnicodeError):
        return False
    return hmac.compare_digest(presented, expected)
