"""Opaque secret-provider boundary.

Only the connector/OIDC boundary may resolve a reference. API responses, queues
and persistence use `SecretReference`, never the resolved value.
"""

from __future__ import annotations

import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Literal

from cyberaudit.config import Settings, get_settings


@dataclass(frozen=True)
class SecretReference:
    uri: str


@dataclass(frozen=True)
class SecretMetadata:
    provider: str
    reference: str
    available: bool
    expires_at: datetime | None = None


@dataclass(frozen=True)
class SecretHealth:
    healthy: bool
    provider: str
    message: str
    checked_at: datetime


class SecretProvider(ABC):
    scheme: str

    @abstractmethod
    def validate_reference(self, reference: SecretReference) -> None: ...

    @abstractmethod
    async def resolve_reference(self, reference: SecretReference) -> str: ...

    @abstractmethod
    async def rotate_reference(self, reference: SecretReference) -> SecretMetadata: ...

    @abstractmethod
    async def get_metadata(self, reference: SecretReference) -> SecretMetadata: ...

    @abstractmethod
    async def health_check(self) -> SecretHealth: ...


class EnvironmentSecretProvider(SecretProvider):
    """Development-only environment resolution with a strict variable allowlist."""

    scheme = "env://"

    def __init__(self, allowed_names: set[str], environment: str) -> None:
        self.allowed_names = allowed_names
        self.environment = environment

    def validate_reference(self, reference: SecretReference) -> None:
        if self.environment not in {"development", "test", "demo"}:
            raise ValueError("Environment secrets are forbidden outside controlled environments")
        if not reference.uri.startswith(self.scheme):
            raise ValueError("Invalid environment secret reference")
        name = reference.uri.removeprefix(self.scheme)
        if name not in self.allowed_names or not name.replace("_", "").isalnum():
            raise ValueError("Environment variable is not allowlisted")

    async def resolve_reference(self, reference: SecretReference) -> str:
        self.validate_reference(reference)
        name = reference.uri.removeprefix(self.scheme)
        value = os.environ.get(name)
        if value is None:
            raise LookupError("Referenced secret is unavailable")
        return value

    async def rotate_reference(self, reference: SecretReference) -> SecretMetadata:
        self.validate_reference(reference)
        raise NotImplementedError("Environment secrets cannot be rotated by CyberAudit")

    async def get_metadata(self, reference: SecretReference) -> SecretMetadata:
        self.validate_reference(reference)
        name = reference.uri.removeprefix(self.scheme)
        return SecretMetadata("environment", reference.uri, name in os.environ)

    async def health_check(self) -> SecretHealth:
        return SecretHealth(
            True,
            "environment",
            "Development provider available; values are never enumerated.",
            datetime.now(timezone.utc),
        )


class ExternalSecretProvider(SecretProvider):
    """Metadata-safe placeholder for provider integrations resolved at deployment."""

    def __init__(
        self,
        provider: Literal["vault", "aws", "azure", "gcp", "kubernetes", "docker"],
    ) -> None:
        self.provider = provider
        self.scheme = {
            "vault": "vault://",
            "aws": "aws-secrets://",
            "azure": "azure-key-vault://",
            "gcp": "gcp-secret://",
            "kubernetes": "kubernetes-secret://",
            "docker": "docker-secret://",
        }[provider]

    def validate_reference(self, reference: SecretReference) -> None:
        if not reference.uri.startswith(self.scheme) or len(reference.uri) > 500:
            raise ValueError(f"Expected an opaque {self.scheme} reference")
        if any(character.isspace() for character in reference.uri):
            raise ValueError("Secret reference cannot contain whitespace")

    async def resolve_reference(self, reference: SecretReference) -> str:
        self.validate_reference(reference)
        raise RuntimeError(
            "External secret resolution requires the provider integration in the runner boundary"
        )

    async def rotate_reference(self, reference: SecretReference) -> SecretMetadata:
        self.validate_reference(reference)
        raise RuntimeError("Rotation must be delegated to the configured secret manager")

    async def get_metadata(self, reference: SecretReference) -> SecretMetadata:
        self.validate_reference(reference)
        return SecretMetadata(self.provider, reference.uri, False)

    async def health_check(self) -> SecretHealth:
        return SecretHealth(
            False,
            self.provider,
            "Provider adapter configured but no runtime identity was verified.",
            datetime.now(timezone.utc),
        )


def secret_provider(settings: Settings | None = None) -> SecretProvider:
    config = settings or get_settings()
    if config.secret_provider == "environment":
        return EnvironmentSecretProvider(
            {
                "CYBERAUDIT_OIDC_CLIENT_SECRET",
                "CYBERAUDIT_STORAGE_CREDENTIAL",
                "CYBERAUDIT_LICENSE_PUBLIC_KEY",
                "CYBERAUDIT_TOTP_SECRET",
            },
            config.environment,
        )
    return ExternalSecretProvider(config.secret_provider)
