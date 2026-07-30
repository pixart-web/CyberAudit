"""Execution runner contracts without arbitrary command execution."""

from __future__ import annotations

import hashlib
import json
import secrets
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

import httpx
from pydantic import BaseModel, ConfigDict, Field

from cyberaudit.redaction import redact


class RunnerRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    operation: Literal["validate_json", "sha256", "connector_read"]
    payload: dict[str, Any] = Field(default_factory=dict)
    timeout_seconds: int = Field(default=30, ge=1, le=300)
    maximum_output_bytes: int = Field(default=1_048_576, ge=1024, le=10_485_760)


@dataclass(frozen=True)
class RunnerSecurityProfile:
    read_only_filesystem: bool = True
    run_as_non_root: bool = True
    drop_all_capabilities: bool = True
    no_new_privileges: bool = True
    process_limit: int = 16
    cpu_limit: float = 1.0
    memory_limit_mb: int = 512
    network_mode: Literal["none", "allowlist"] = "none"
    egress_allowlist: tuple[str, ...] = ()
    metadata_service_blocked: bool = True
    docker_socket_mounted: bool = False
    host_mounts: tuple[str, ...] = ()


@dataclass(frozen=True)
class RunnerResult:
    execution_id: str
    status: Literal["completed", "failed", "cancelled", "timed_out", "unavailable"]
    started_at: datetime
    completed_at: datetime
    output: dict[str, Any]
    output_hash: str
    metadata: dict[str, Any] = field(default_factory=dict)
    error_code: str | None = None


class ExecutionRunner(ABC):
    @abstractmethod
    async def execute(self, request: RunnerRequest) -> RunnerResult: ...

    @abstractmethod
    async def cancel(self, execution_id: str) -> None: ...

    @abstractmethod
    async def health_check(self) -> dict[str, Any]: ...


class LocalRestrictedRunner(ExecutionRunner):
    """Development runner with a fixed internal operation registry."""

    def __init__(self) -> None:
        self.cancelled: set[str] = set()
        self.security = RunnerSecurityProfile()

    async def execute(self, request: RunnerRequest) -> RunnerResult:
        execution_id = secrets.token_hex(16)
        started = datetime.now(timezone.utc)
        if request.operation == "validate_json":
            output = {"valid": True, "keys": sorted(request.payload)[:100]}
        elif request.operation == "sha256":
            value = str(request.payload.get("value", ""))[: request.maximum_output_bytes]
            output = {"sha256": hashlib.sha256(value.encode()).hexdigest()}
        else:
            output = {
                "accepted": True,
                "message": "Connector execution is delegated to its closed SDK client.",
            }
        if execution_id in self.cancelled:
            status: Literal["completed", "cancelled"] = "cancelled"
            output = {}
        else:
            status = "completed"
        sanitized = redact(output)
        canonical = json.dumps(sanitized, sort_keys=True, separators=(",", ":"))
        if len(canonical.encode()) > request.maximum_output_bytes:
            raise ValueError("Runner output exceeds configured limit")
        completed = datetime.now(timezone.utc)
        return RunnerResult(
            execution_id,
            status,
            started,
            completed,
            sanitized,
            hashlib.sha256(canonical.encode()).hexdigest(),
            metadata={"runner": "local_restricted", "external_process": False},
        )

    async def cancel(self, execution_id: str) -> None:
        self.cancelled.add(execution_id)

    async def health_check(self) -> dict[str, Any]:
        return {
            "healthy": True,
            "runner": "local_restricted",
            "production_ready": False,
        }


class EphemeralRunnerDescriptor(ExecutionRunner):
    """Fail-closed descriptor for external Docker/Kubernetes runner controllers."""

    def __init__(self, runner_type: Literal["docker_ephemeral", "kubernetes_job"]) -> None:
        self.runner_type = runner_type
        self.security = RunnerSecurityProfile(
            network_mode="allowlist",
            egress_allowlist=(),
        )

    async def execute(self, request: RunnerRequest) -> RunnerResult:
        now = datetime.now(timezone.utc)
        return RunnerResult(
            secrets.token_hex(16),
            "unavailable",
            now,
            now,
            {},
            hashlib.sha256(b"{}").hexdigest(),
            metadata={"runner": self.runner_type, "privileged": False},
            error_code="RUNNER_CONTROLLER_NOT_CONFIGURED",
        )

    async def cancel(self, execution_id: str) -> None:
        return None

    async def health_check(self) -> dict[str, Any]:
        return {
            "healthy": False,
            "runner": self.runner_type,
            "message": "Controller integration is not configured.",
        }


class EphemeralRunnerController(ExecutionRunner):
    """HTTPS client for a separately privileged, fixed-spec runner controller."""

    _images = {
        "validate_json": "registry.invalid/cyberaudit/runner-json@sha256:" + "1" * 64,
        "sha256": "registry.invalid/cyberaudit/runner-hash@sha256:" + "2" * 64,
        "connector_read": "registry.invalid/cyberaudit/runner-connector@sha256:" + "3" * 64,
    }

    def __init__(
        self,
        runner_type: Literal["docker_ephemeral", "kubernetes_job"],
        controller_url: str,
        token_file: Path,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        if not controller_url.startswith("https://"):
            raise ValueError("Runner controller must use HTTPS")
        self.runner_type = runner_type
        self.controller_url = controller_url.rstrip("/")
        self.token_file = token_file
        self.transport = transport
        self.security = RunnerSecurityProfile()

    def _token(self) -> str:
        try:
            token = self.token_file.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise RuntimeError("Runner workload token is unavailable") from exc
        if not token or len(token) > 8192 or any(character.isspace() for character in token):
            raise RuntimeError("Runner workload token is invalid")
        return token

    def build_spec(self, request: RunnerRequest) -> dict[str, Any]:
        """Build an immutable execution declaration; commands cannot be supplied."""
        image = self._images[request.operation]
        security = {
            "read_only_filesystem": True,
            "run_as_non_root": True,
            "drop_capabilities": ["ALL"],
            "no_new_privileges": True,
            "process_limit": self.security.process_limit,
            "cpu_limit": self.security.cpu_limit,
            "memory_limit_mb": self.security.memory_limit_mb,
            "network_mode": "none",
            "metadata_service_blocked": True,
            "docker_socket_mounted": False,
            "host_mounts": [],
        }
        return {
            "api_version": "cyberaudit.io/runner/v1",
            "runner_type": self.runner_type,
            "operation": request.operation,
            "image": image,
            "input": redact(request.payload),
            "limits": {
                "timeout_seconds": request.timeout_seconds,
                "maximum_output_bytes": request.maximum_output_bytes,
            },
            "security": security,
        }

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=self.controller_url,
            headers={"Authorization": f"Bearer {self._token()}"},
            timeout=httpx.Timeout(10),
            follow_redirects=False,
            transport=self.transport,
        )

    async def execute(self, request: RunnerRequest) -> RunnerResult:
        started = datetime.now(timezone.utc)
        async with self._client() as client:
            response = await client.post("/v1/executions", json=self.build_spec(request))
        response.raise_for_status()
        payload = response.json()
        output = redact(payload.get("output", {}))
        canonical = json.dumps(output, sort_keys=True, separators=(",", ":")).encode()
        if len(canonical) > request.maximum_output_bytes:
            raise ValueError("Runner output exceeds configured limit")
        status = payload.get("status")
        if status not in {"completed", "failed", "cancelled", "timed_out"}:
            raise ValueError("Runner controller returned an invalid terminal state")
        return RunnerResult(
            str(payload["execution_id"]),
            status,
            started,
            datetime.now(timezone.utc),
            output,
            hashlib.sha256(canonical).hexdigest(),
            metadata={
                "runner": self.runner_type,
                "ephemeral": True,
                "image": self._images[request.operation],
            },
            error_code=payload.get("error_code"),
        )

    async def cancel(self, execution_id: str) -> None:
        if (
            not execution_id
            or len(execution_id) > 128
            or not execution_id.replace("-", "").isalnum()
        ):
            raise ValueError("Invalid runner execution identifier")
        async with self._client() as client:
            response = await client.post(f"/v1/executions/{execution_id}/cancel")
        response.raise_for_status()

    async def health_check(self) -> dict[str, Any]:
        try:
            async with self._client() as client:
                response = await client.get("/health")
            response.raise_for_status()
            payload = response.json()
            return {
                "healthy": payload.get("status") == "ok",
                "runner": self.runner_type,
                "controller_authenticated": True,
            }
        except (httpx.HTTPError, RuntimeError, ValueError):
            return {
                "healthy": False,
                "runner": self.runner_type,
                "controller_authenticated": False,
            }
