"""Local-account password policy used only when local authentication is enabled."""

from __future__ import annotations

import re

COMMON_PASSWORDS = {
    "password",
    "password123",
    "changeme123!",
    "qwerty123456",
    "administrator",
}


def validate_password_policy(password: str, *, email: str | None = None) -> str:
    if len(password) < 14 or len(password) > 128:
        raise ValueError("Password must contain between 14 and 128 characters")
    if password.lower() in COMMON_PASSWORDS:
        raise ValueError("Password is present in the local denylist")
    if email and email.split("@", 1)[0].lower() in password.lower():
        raise ValueError("Password must not contain the email local part")
    classes = sum(
        bool(re.search(pattern, password))
        for pattern in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]")
    )
    if classes < 3:
        raise ValueError("Password must use at least three character classes")
    return password
