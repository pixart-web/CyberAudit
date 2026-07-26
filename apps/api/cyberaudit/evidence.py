import hashlib
import json
import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from pydantic import BaseModel


class SanitizedEvidence(BaseModel):
    content: str
    content_hash: str
    size_bytes: int
    redacted: bool
    redaction_count: int


class EvidenceSanitizer:
    MAX_EXCERPT_BYTES = 262_144
    _SENSITIVE_NAMES = {
        "authorization",
        "cookie",
        "set-cookie",
        "password",
        "passwd",
        "token",
        "access_token",
        "refresh_token",
        "api_key",
        "apikey",
        "secret",
        "session",
        "sessionid",
    }
    _VALUE_PATTERNS = (
        re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+"),
        re.compile(r"(?i)\b(?:api[_-]?key|token|password|secret)\s*[:=]\s*[^\s,;]+"),
        re.compile(r"\b[A-Fa-f0-9]{32,}\b"),
    )
    _EMAIL = re.compile(r"(?<![\w.+-])[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}(?![\w.-])")

    def __init__(self, *, redact_emails: bool = False) -> None:
        self.redact_emails = redact_emails

    def sanitize_text(self, content: str) -> SanitizedEvidence:
        raw = content.encode("utf-8", errors="replace")
        if len(raw) > self.MAX_EXCERPT_BYTES:
            raw = raw[: self.MAX_EXCERPT_BYTES]
            content = raw.decode("utf-8", errors="replace")
        count = 0
        for pattern in self._VALUE_PATTERNS:
            content, replacements = pattern.subn("[REDACTED]", content)
            count += replacements
        if self.redact_emails:
            content, replacements = self._EMAIL.subn("[EMAIL REDACTED]", content)
            count += replacements
        encoded = content.encode()
        return SanitizedEvidence(
            content=content,
            content_hash=hashlib.sha256(encoded).hexdigest(),
            size_bytes=len(encoded),
            redacted=count > 0,
            redaction_count=count,
        )

    def sanitize_headers(self, headers: dict[str, list[str]]) -> SanitizedEvidence:
        safe: dict[str, list[str]] = {}
        redactions = 0
        for name, values in headers.items():
            key = name.lower()
            if key in {"cookie", "authorization", "proxy-authorization"}:
                safe[key] = ["[REDACTED]"]
                redactions += len(values)
            elif key == "set-cookie":
                safe[key] = [self._sanitize_set_cookie(value) for value in values]
                redactions += len(values)
            else:
                safe[key] = values
        result = self.sanitize_text(json.dumps(safe, ensure_ascii=False, sort_keys=True))
        return result.model_copy(
            update={
                "redacted": result.redacted or redactions > 0,
                "redaction_count": result.redaction_count + redactions,
            }
        )

    def sanitize_mapping(self, value: dict[str, Any]) -> SanitizedEvidence:
        def clean(item: Any, key: str = "") -> Any:
            if key.lower() in self._SENSITIVE_NAMES:
                return "[REDACTED]"
            if isinstance(item, dict):
                return {str(k): clean(v, str(k)) for k, v in item.items()}
            if isinstance(item, list):
                return [clean(child) for child in item]
            return item

        original = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
        cleaned = json.dumps(clean(value), ensure_ascii=False, sort_keys=True, default=str)
        result = self.sanitize_text(cleaned)
        return result.model_copy(update={"redacted": result.redacted or cleaned != original})

    def sanitize_url(self, value: str) -> str:
        parsed = urlsplit(value)
        pairs = []
        for key, item in parse_qsl(parsed.query, keep_blank_values=True):
            pairs.append((key, "[REDACTED]" if key.lower() in self._SENSITIVE_NAMES else item))
        hostname = parsed.hostname or ""
        netloc = hostname
        if parsed.port:
            netloc = f"{hostname}:{parsed.port}"
        return urlunsplit((parsed.scheme, netloc, parsed.path, urlencode(pairs), ""))

    @staticmethod
    def _sanitize_set_cookie(value: str) -> str:
        parts = [part.strip() for part in value.split(";")]
        name = parts[0].split("=", 1)[0].strip() if parts else "cookie"
        attributes = [part for part in parts[1:] if part]
        return "; ".join([f"{name}=[REDACTED]", *attributes])
