"""Minimal W3C trace-context handling with no payload capture."""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass

TRACEPARENT = re.compile(r"^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$")


@dataclass(frozen=True)
class TraceContext:
    trace_id: str
    parent_id: str
    sampled: bool

    def child_header(self) -> str:
        return f"00-{self.trace_id}-{secrets.token_hex(8)}-{'01' if self.sampled else '00'}"


def trace_context(header: str | None) -> TraceContext:
    match = TRACEPARENT.fullmatch((header or "").lower())
    if match and match.group(1) != "0" * 32 and match.group(2) != "0" * 16:
        return TraceContext(match.group(1), match.group(2), bool(int(match.group(3), 16) & 1))
    return TraceContext(secrets.token_hex(16), secrets.token_hex(8), False)
