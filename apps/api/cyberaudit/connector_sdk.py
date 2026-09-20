"""Internal SDK for scoped, schema-bound and read-only connectors."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal
from urllib.parse import urljoin, urlparse

import httpx
from pydantic import BaseModel, ConfigDict, Field, field_validator

from cyberaudit.redaction import redact
from cyberaudit.secrets import SecretReference


class ConnectorManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    code: str
    version: str
    provider: str
    capabilities: list[str]
    required_permissions: list[str]
    optional_permissions: list[str] = Field(default_factory=list)
    data_categories: list[str]
    rate_limit_per_minute: int = Field(ge=1, le=6000)
    pagination_strategy: Literal["none", "cursor", "next_link", "page_token"]
    incremental_sync_support: bool
    external_io: bool
    write_capabilities: list[str] = Field(default_factory=list, max_length=0)
    security_classification: Literal["internal", "confidential", "restricted"]
    supported_runner: Literal["local_restricted", "docker_ephemeral", "kubernetes_job"]
    minimum_platform_version: str
    allowed_origins: list[str]

    @field_validator("allowed_origins")
    @classmethod
    def https_origins(cls, values: list[str]) -> list[str]:
        if not values or any(
            urlparse(item).scheme != "https" or urlparse(item).path not in {"", "/"}
            for item in values
        ):
            raise ValueError("Connector origins must be HTTPS origins without paths")
        return values


@dataclass(frozen=True)
class ConnectorContext:
    organization_id: str
    connector_id: str
    scope: tuple[str, ...]
    credential_reference: SecretReference
    cancellation_event: asyncio.Event
    deadline: datetime


@dataclass(frozen=True)
class ConnectorCheckpoint:
    cursor: str | None = None
    observed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass(frozen=True)
class ConnectorResult:
    records: list[dict[str, Any]]
    checkpoint: ConnectorCheckpoint
    evidence: list[dict[str, Any]]
    warnings: list[str]


class ScopedReadOnlyClient:
    def __init__(
        self,
        *,
        allowed_origins: list[str],
        bearer_token: str,
        timeout_seconds: int = 20,
        maximum_bytes: int = 5_242_880,
    ) -> None:
        self.allowed_origins = {item.rstrip("/") for item in allowed_origins}
        self._bearer_token = bearer_token
        self.timeout_seconds = timeout_seconds
        self.maximum_bytes = maximum_bytes

    def validate_url(self, url: str) -> None:
        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        if parsed.scheme != "https" or origin not in self.allowed_origins:
            raise ValueError("Connector URL is outside its declared HTTPS origin")
        if parsed.username or parsed.password or parsed.fragment:
            raise ValueError("Connector URL contains forbidden components")

    async def get_json(self, url: str, params: dict[str, str] | None = None) -> dict[str, Any]:
        self.validate_url(url)
        async with httpx.AsyncClient(
            timeout=self.timeout_seconds, follow_redirects=False, verify=True
        ) as client:
            response = await client.get(
                url,
                params=params,
                headers={
                    "authorization": f"Bearer {self._bearer_token}",
                    "accept": "application/json",
                },
            )
            response.raise_for_status()
            if len(response.content) > self.maximum_bytes:
                raise ValueError("Connector response exceeds maximum size")
            if "application/json" not in response.headers.get("content-type", ""):
                raise ValueError("Connector response is not JSON")
            payload = response.json()
        if not isinstance(payload, dict):
            raise ValueError("Connector response root must be an object")
        return redact(payload)

    def validate_next_link(self, current_url: str, next_link: str) -> str:
        resolved = urljoin(current_url, next_link)
        self.validate_url(resolved)
        return resolved


LIVE_CONNECTOR_MANIFESTS = {
    "entra": ConnectorManifest(
        name="Microsoft Entra ID",
        code="cyberaudit.entra.live_read_only",
        version="0.1.0",
        provider="microsoft",
        capabilities=["identity_inventory", "application_inventory"],
        required_permissions=[
            "User.Read.All",
            "Group.Read.All",
            "Application.Read.All",
        ],
        data_categories=["identities", "groups", "applications"],
        rate_limit_per_minute=600,
        pagination_strategy="next_link",
        incremental_sync_support=True,
        external_io=True,
        security_classification="confidential",
        supported_runner="kubernetes_job",
        minimum_platform_version="0.2.0",
        allowed_origins=["https://graph.microsoft.com"],
    ),
    "aws": ConnectorManifest(
        name="AWS Inventory",
        code="cyberaudit.aws.live_read_only",
        version="0.1.0",
        provider="aws",
        capabilities=["account_inventory", "resource_inventory"],
        required_permissions=["SecurityAudit"],
        data_categories=["cloud_accounts", "cloud_resources"],
        rate_limit_per_minute=300,
        pagination_strategy="page_token",
        incremental_sync_support=True,
        external_io=True,
        security_classification="confidential",
        supported_runner="kubernetes_job",
        minimum_platform_version="0.2.0",
        allowed_origins=["https://organizations.amazonaws.com"],
    ),
    "azure": ConnectorManifest(
        name="Azure Resource Manager",
        code="cyberaudit.azure.live_read_only",
        version="0.1.0",
        provider="azure",
        capabilities=["subscription_inventory", "resource_inventory"],
        required_permissions=["Reader"],
        data_categories=["cloud_accounts", "cloud_resources"],
        rate_limit_per_minute=600,
        pagination_strategy="next_link",
        incremental_sync_support=True,
        external_io=True,
        security_classification="confidential",
        supported_runner="kubernetes_job",
        minimum_platform_version="0.2.0",
        allowed_origins=["https://management.azure.com"],
    ),
    "gcp": ConnectorManifest(
        name="Google Cloud Asset Inventory",
        code="cyberaudit.gcp.live_read_only",
        version="0.1.0",
        provider="gcp",
        capabilities=["project_inventory", "resource_inventory"],
        required_permissions=["roles/cloudasset.viewer"],
        data_categories=["cloud_accounts", "cloud_resources"],
        rate_limit_per_minute=600,
        pagination_strategy="page_token",
        incremental_sync_support=True,
        external_io=True,
        security_classification="confidential",
        supported_runner="kubernetes_job",
        minimum_platform_version="0.2.0",
        allowed_origins=["https://cloudasset.googleapis.com"],
    ),
    "kubernetes": ConnectorManifest(
        name="Kubernetes API Inventory",
        code="cyberaudit.kubernetes.live_read_only",
        version="0.1.0",
        provider="kubernetes",
        capabilities=["cluster_inventory", "workload_posture"],
        required_permissions=["get", "list", "watch"],
        data_categories=["clusters", "workloads", "rbac"],
        rate_limit_per_minute=1200,
        pagination_strategy="cursor",
        incremental_sync_support=True,
        external_io=True,
        security_classification="restricted",
        supported_runner="kubernetes_job",
        minimum_platform_version="0.2.0",
        allowed_origins=["https://kubernetes.default.svc"],
    ),
}


class ConnectorContractTestSuite:
    """Reusable, side-effect-free checks every connector must pass before registration."""

    @staticmethod
    def validate_manifest(manifest: ConnectorManifest, platform_version: str) -> list[str]:
        failures: list[str] = []
        if manifest.write_capabilities:
            failures.append("WRITE_CAPABILITIES_FORBIDDEN")
        if not manifest.code.startswith("cyberaudit."):
            failures.append("INVALID_CODE_NAMESPACE")
        if manifest.minimum_platform_version > platform_version:
            failures.append("PLATFORM_VERSION_UNSUPPORTED")
        if any(
            permission.lower().endswith((".write", ".write.all"))
            for permission in manifest.required_permissions
        ):
            failures.append("WRITE_PERMISSION_DECLARED")
        if manifest.external_io and not manifest.allowed_origins:
            failures.append("ORIGIN_ALLOWLIST_REQUIRED")
        return failures

    @staticmethod
    def validate_checkpoint(previous: ConnectorCheckpoint, current: ConnectorCheckpoint) -> None:
        if current.observed_at < previous.observed_at:
            raise ValueError("Connector checkpoints must be monotonic")

    @classmethod
    def assert_compatible(cls, manifest: ConnectorManifest, platform_version: str) -> None:
        failures = cls.validate_manifest(manifest, platform_version)
        if failures:
            raise ValueError("Connector contract rejected: " + ", ".join(failures))
