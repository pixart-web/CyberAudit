"""Central defensive redaction for logs, errors, traces and diagnostics."""

from __future__ import annotations

import re
from typing import Any

SENSITIVE_KEYS = {
    "access_token",
    "api_key",
    "authorization",
    "client_secret",
    "connection_string",
    "cookie",
    "password",
    "private_key",
    "refresh_token",
    "secret",
    "signed_url",
    "token",
}
PATTERNS = (
    re.compile(r"(?i)\b(bearer)\s+[a-z0-9._~+/=-]+"),
    re.compile(r"(?i)\b(password|token|secret|api[_-]?key|client[_-]?secret)\b\s*[:=]\s*[^,\s;]+"),
    re.compile(r"(?i)(postgres(?:ql)?|redis|mongodb)://[^@\s]+@"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
)


def redact_text(value: str, maximum: int = 10_000) -> str:
    result = value.replace("\x00", "")[:maximum]
    for pattern in PATTERNS:
        if "PRIVATE KEY" in pattern.pattern:
            result = pattern.sub("[REDACTED PRIVATE KEY]", result)
        elif "://" in pattern.pattern:
            result = pattern.sub(r"\1://[REDACTED]@", result)
        else:
            result = pattern.sub(r"\1 [REDACTED]", result)
    return result


def redact(value: Any, *, depth: int = 0) -> Any:
    if depth > 8:
        return "[TRUNCATED]"
    if isinstance(value, dict):
        return {
            str(key)[:200]: (
                "[REDACTED]"
                if str(key).lower().replace("-", "_") in SENSITIVE_KEYS
                else redact(item, depth=depth + 1)
            )
            for key, item in list(value.items())[:1000]
        }
    if isinstance(value, (list, tuple)):
        return [redact(item, depth=depth + 1) for item in value[:1000]]
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, (bool, int, float)) or value is None:
        return value
    return redact_text(str(value), 1000)
