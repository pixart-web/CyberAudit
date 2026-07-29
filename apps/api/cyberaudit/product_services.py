"""Feature, licensing, telemetry and lifecycle services."""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from cyberaudit.hardening_models import LicenseRecord
from cyberaudit.redaction import redact

EDITIONS = {
    "community": {
        "inventory.basic",
        "findings.read",
        "dashboard.basic",
    },
    "professional": {
        "inventory.basic",
        "findings.read",
        "dashboard.basic",
        "connectors.multiple",
        "soc",
        "grc",
        "reports",
    },
    "enterprise": {
        "inventory.basic",
        "findings.read",
        "dashboard.basic",
        "connectors.multiple",
        "soc",
        "grc",
        "reports",
        "sso",
        "mfa.advanced",
        "ha",
        "dr",
        "connector_sdk",
        "zero_trust",
        "knowledge_graph",
        "ai.advisory",
    },
}
TELEMETRY_FIELDS = {
    "version",
    "edition",
    "operating_system",
    "update_success",
    "aggregated_error_code",
    "aggregated_feature",
    "health_status",
}
LIFECYCLE_TRANSITIONS = {
    "active": {"archived", "legal_hold", "pending_deletion"},
    "archived": {"active", "legal_hold", "pending_deletion"},
    "legal_hold": {"active", "archived"},
    "pending_deletion": {"active", "deleted"},
    "deleted": set(),
}


def validate_lifecycle_transition(current: str, requested: str, *, legal_hold: bool) -> None:
    if legal_hold and requested in {"pending_deletion", "deleted"}:
        raise ValueError("Object on legal hold cannot be deleted")
    if requested not in LIFECYCLE_TRANSITIONS.get(current, set()):
        raise ValueError(f"Invalid lifecycle transition: {current} -> {requested}")


def telemetry_preview(payload: dict[str, Any]) -> dict[str, Any]:
    unexpected = set(payload) - TELEMETRY_FIELDS
    if unexpected:
        raise ValueError(f"Telemetry contains forbidden fields: {sorted(unexpected)}")
    return redact(payload)


@dataclass(frozen=True)
class LicenseDecision:
    allowed: bool
    reason: str
    read_only: bool


class LicenseService:
    @staticmethod
    def community(organization_id: str) -> LicenseRecord:
        payload = {"edition": "community", "organization_id": organization_id}
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return LicenseRecord(
            organization_id=organization_id,
            edition="community",
            provider="community",
            license_id=f"community-{organization_id}",
            payload_hash=hashlib.sha256(canonical.encode()).hexdigest(),
            capabilities=sorted(EDITIONS["community"]),
            status="active",
        )

    @staticmethod
    def verify_offline(
        encoded_payload: str, encoded_signature: str, encoded_public_key: str
    ) -> dict[str, Any]:
        payload = base64.urlsafe_b64decode(encoded_payload + "=" * (-len(encoded_payload) % 4))
        signature = base64.urlsafe_b64decode(
            encoded_signature + "=" * (-len(encoded_signature) % 4)
        )
        public_key = base64.urlsafe_b64decode(
            encoded_public_key + "=" * (-len(encoded_public_key) % 4)
        )
        try:
            Ed25519PublicKey.from_public_bytes(public_key).verify(signature, payload)
        except (ValueError, InvalidSignature) as exc:
            raise ValueError("License signature is invalid") from exc
        document = json.loads(payload)
        if not isinstance(document, dict) or document.get("edition") not in EDITIONS:
            raise ValueError("License payload is invalid")
        return document

    @staticmethod
    def evaluate(record: LicenseRecord | None, capability: str) -> LicenseDecision:
        if record is None:
            return LicenseDecision(capability in EDITIONS["community"], "COMMUNITY_DEFAULT", False)
        now = datetime.now(timezone.utc)
        if record.expires_at and record.expires_at <= now:
            in_grace = bool(record.grace_until and record.grace_until > now)
            return LicenseDecision(
                capability in record.capabilities and in_grace,
                "LICENSE_GRACE" if in_grace else "LICENSE_EXPIRED",
                True,
            )
        return LicenseDecision(
            capability in record.capabilities,
            ("LICENSE_ALLOWED" if capability in record.capabilities else "CAPABILITY_MISSING"),
            False,
        )
