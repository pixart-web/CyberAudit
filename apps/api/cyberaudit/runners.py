"""Execution runner contracts without arbitrary command execution."""

from __future__ import annotations

import hashlib
import json
import secrets
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal

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
