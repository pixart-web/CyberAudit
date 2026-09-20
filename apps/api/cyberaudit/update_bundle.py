"""Offline / air-gapped update bundles (Phase 10.3.7).

A CyberAudit-Update bundle (``.caup``) carries a signed manifest describing
what it contains -- an application update, a knowledge pack, vulnerability
metadata, threat intelligence, or a model manifest -- and a checksum for
every file it references. Manifests are Ed25519-signed; verification is
real asymmetric cryptography against a set of administrator-configured
trusted public keys, never "trusted because it was uploaded."

This module validates and reports on a bundle. It never executes anything
from one, never extracts files, and never applies an update by itself:
staging, migration preview, service restart and rollback are installer/
runtime concerns that belong to Phase 10.3.8's packaging work, which is
architecture-only in this phase (see ADR-029). Treat a bundle here as
untrusted input until every check below passes.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_public_key,
)
from pydantic import BaseModel, ConfigDict, Field, ValidationError

BundleType = Literal[
    "application_update",
    "knowledge_pack",
    "vulnerability_metadata",
    "threat_intelligence",
    "model_manifest",
]


class UpdateManifest(BaseModel):
    """The signed, canonical description of one update bundle."""

    model_config = ConfigDict(extra="forbid")
    bundle_id: str = Field(min_length=8, max_length=200)
    bundle_type: BundleType
    version: str = Field(min_length=1, max_length=40)
    created_at: datetime
    min_compatible_app_version: str
    max_compatible_app_version: str | None = None
    rollback_of: str | None = None
    provenance: dict[str, str] = Field(default_factory=dict)
    # filename -> sha256 hex digest, for every file the bundle carries.
    checksums: dict[str, str] = Field(default_factory=dict)

    def canonical_bytes(self) -> bytes:
        """The exact byte sequence that was signed: stable field order."""
        return json.dumps(
            self.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
        ).encode()


@dataclass(frozen=True)
class BundleValidationResult:
    accepted: bool
    bundle_id: str | None
    bundle_type: str | None
    reasons: list[str] = field(default_factory=list)
    checked_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class TrustedKeyStore:
    """The administrator-configured set of keys a bundle's signature may match.

    A bundle is never trusted merely because it was manually uploaded; its
    signature must verify against one of these keys, configured out of band
    (never inside the bundle itself).
    """

    def __init__(self, public_keys_pem: list[bytes]):
        self._keys: list[Ed25519PublicKey] = []
        for pem in public_keys_pem:
            key = load_pem_public_key(pem)
            if not isinstance(key, Ed25519PublicKey):
                raise ValueError("Only Ed25519 public keys are supported for update signing")
            self._keys.append(key)

    def verify(self, message: bytes, signature: bytes) -> bool:
        for key in self._keys:
            try:
                key.verify(signature, message)
                return True
            except InvalidSignature:
                continue
        return False


def sign_manifest(manifest: UpdateManifest, private_key: Ed25519PrivateKey) -> bytes:
    """Signs a manifest. Used by release tooling and by tests; never called

    from a code path that processes an incoming, untrusted bundle.
    """
    return private_key.sign(manifest.canonical_bytes())


def generate_signing_keypair() -> tuple[Ed25519PrivateKey, bytes]:
    """Generates a new Ed25519 keypair; returns the private key and the

    PEM-encoded public key an administrator would distribute as trusted.
    """
    private_key = Ed25519PrivateKey.generate()
    public_pem = private_key.public_key().public_bytes(
        encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo
    )
    return private_key, public_pem


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


class UpdateBundleService:
    """Validates an offline update bundle. Never stages or applies one."""

    def __init__(self, trusted_keys: TrustedKeyStore, *, current_app_version: str):
        self.trusted_keys = trusted_keys
        self.current_app_version = current_app_version

    def validate(
        self,
        manifest_json: bytes,
        signature: bytes,
        files: dict[str, bytes] | None = None,
    ) -> BundleValidationResult:
        reasons: list[str] = []
        try:
            manifest = UpdateManifest.model_validate_json(manifest_json)
        except (ValidationError, ValueError) as exc:
            return BundleValidationResult(False, None, None, [f"Malformed manifest: {exc}"])

        if not self.trusted_keys.verify(manifest.canonical_bytes(), signature):
            reasons.append("Signature does not match any trusted key")

        if not self._version_compatible(manifest):
            reasons.append(
                "Bundle is not compatible with this installation's app version "
                f"({self.current_app_version})"
            )

        for filename, expected_digest in manifest.checksums.items():
            content = (files or {}).get(filename)
            if content is None:
                reasons.append(f"Manifest references a missing file: {filename}")
                continue
            if _sha256(content) != expected_digest:
                reasons.append(f"Checksum mismatch for {filename}")

        return BundleValidationResult(
            accepted=not reasons,
            bundle_id=manifest.bundle_id,
            bundle_type=manifest.bundle_type,
            reasons=reasons,
        )

    def _version_compatible(self, manifest: UpdateManifest) -> bool:
        def parse(value: str) -> tuple[int, ...]:
            return tuple(int(part) for part in value.split("."))

        try:
            current = parse(self.current_app_version)
            minimum = parse(manifest.min_compatible_app_version)
        except ValueError:
            return False
        if current < minimum:
            return False
        if manifest.max_compatible_app_version:
            try:
                maximum = parse(manifest.max_compatible_app_version)
            except ValueError:
                return False
            if current > maximum:
                return False
        return True
