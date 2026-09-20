"""Opaque secret-provider boundary.

Only the connector/OIDC boundary may resolve a reference. API responses, queues
and persistence use `SecretReference`, never the resolved value.
"""

from __future__ import annotations

import os
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal
from urllib.parse import parse_qs, urlparse

import httpx

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
    version: str | None = None


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


@dataclass(frozen=True)
class VaultReference:
    mount: str
    path: str
    field: str
    version: int | None


class VaultSecretProvider(SecretProvider):
    """Vault KV v2 client using a deployment-owned token and closed references."""

    scheme = "vault://"
    _segment = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")

    def __init__(
        self,
        address: str,
        token_file: Path,
        namespace: str | None = None,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        parsed_address = urlparse(address)
        if parsed_address.scheme != "https" or not parsed_address.netloc:
            raise ValueError("Vault address must be an absolute HTTPS URL")
        if parsed_address.path not in {"", "/"} or parsed_address.query or parsed_address.fragment:
            raise ValueError("Vault address cannot contain a path, query or fragment")
        self.address = address.rstrip("/")
        self.token_file = token_file
        self.namespace = namespace
        self.transport = transport

    def _parse(self, reference: SecretReference) -> VaultReference:
        if len(reference.uri) > 500 or any(character.isspace() for character in reference.uri):
            raise ValueError("Invalid Vault secret reference")
        parsed = urlparse(reference.uri)
        if parsed.scheme != "vault" or not parsed.netloc or not parsed.fragment:
            raise ValueError("Expected vault://mount/path?version=N#field")
        mount = parsed.netloc
        path_parts = [part for part in parsed.path.split("/") if part]
        if (
            not self._segment.fullmatch(mount)
            or not path_parts
            or any(not self._segment.fullmatch(part) for part in path_parts)
            or not self._segment.fullmatch(parsed.fragment)
        ):
            raise ValueError("Vault reference contains an unsafe segment")
        query = parse_qs(parsed.query, strict_parsing=True)
        if set(query) - {"version"} or any(len(values) != 1 for values in query.values()):
            raise ValueError("Vault reference contains unsupported parameters")
        version: int | None = None
        if "version" in query:
            try:
                version = int(query["version"][0])
            except ValueError as exc:
                raise ValueError("Vault secret version must be an integer") from exc
            if version < 1:
                raise ValueError("Vault secret version must be positive")
        return VaultReference(mount, "/".join(path_parts), parsed.fragment, version)

    def validate_reference(self, reference: SecretReference) -> None:
        self._parse(reference)

    def _token(self) -> str:
        try:
            token = self.token_file.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise RuntimeError("Vault workload token is unavailable") from exc
        if not token or len(token) > 8192 or any(character.isspace() for character in token):
            raise RuntimeError("Vault workload token is invalid")
        return token

    def _headers(self) -> dict[str, str]:
        headers = {"X-Vault-Token": self._token()}
        if self.namespace:
            headers["X-Vault-Namespace"] = self.namespace
        return headers

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=self.address,
            headers=self._headers(),
            follow_redirects=False,
            timeout=httpx.Timeout(5.0),
            transport=self.transport,
        )

    async def resolve_reference(self, reference: SecretReference) -> str:
        parsed = self._parse(reference)
        params = {"version": str(parsed.version)} if parsed.version else None
        async with self._client() as client:
            response = await client.get(
                f"/v1/{parsed.mount}/data/{parsed.path}",
                params=params,
            )
        if response.status_code == 404:
            raise LookupError("Referenced Vault secret is unavailable")
        response.raise_for_status()
        payload = response.json()
        value = payload.get("data", {}).get("data", {}).get(parsed.field)
        if not isinstance(value, str):
            raise LookupError("Referenced Vault secret field is unavailable")
        return value

    async def rotate_reference(self, reference: SecretReference) -> SecretMetadata:
        self.validate_reference(reference)
        raise RuntimeError(
            "Vault rotation requires an approved provider-side workflow; "
            "CyberAudit never receives replacement secret values"
        )

    async def get_metadata(self, reference: SecretReference) -> SecretMetadata:
        parsed = self._parse(reference)
        async with self._client() as client:
            response = await client.get(f"/v1/{parsed.mount}/metadata/{parsed.path}")
        if response.status_code == 404:
            return SecretMetadata("vault", reference.uri, False)
        response.raise_for_status()
        metadata = response.json().get("data", {})
        current_version = metadata.get("current_version")
        return SecretMetadata(
            "vault",
            reference.uri,
            True,
            version=str(current_version) if current_version is not None else None,
        )

    async def health_check(self) -> SecretHealth:
        try:
            async with self._client() as client:
                response = await client.get("/v1/sys/health")
            healthy = response.status_code == 200
            message = "Vault is active and workload authentication succeeded"
            if not healthy:
                message = f"Vault health check returned status {response.status_code}"
        except (httpx.HTTPError, RuntimeError, OSError):
            healthy = False
            message = "Vault health or workload authentication check failed"
        return SecretHealth(
            healthy,
            "vault",
            message,
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
    if config.secret_provider == "vault":
        if not config.vault_address:
            raise ValueError("Vault address is required")
        return VaultSecretProvider(
            config.vault_address,
            config.vault_token_file,
            config.vault_namespace,
        )
    return ExternalSecretProvider(config.secret_provider)
