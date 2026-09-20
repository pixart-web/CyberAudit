"""Contracts for a future isolated runner.

No generic container or command execution is implemented in this phase.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from pydantic import BaseModel, Field

from cyberaudit.adapters import ExecutionSandboxConfig, NormalizedTarget


class RunnerRequest(BaseModel):
    job_id: str
    target: NormalizedTarget
    calculated_policy: dict[str, object]
    validated_configuration: dict[str, object]
    execution_token: str
    output_destination: str
    sandbox: ExecutionSandboxConfig


class ExecutionTokenRecord(BaseModel):
    job_id: str
    token_hash: str
    expires_at: datetime
    used: bool = False


class InMemoryOneTimeExecutionTokens:
    """Development contract; production implementation belongs in Redis."""

    def __init__(self) -> None:
        self._records: dict[str, ExecutionTokenRecord] = {}

    def issue(self, job_id: str, ttl_seconds: int = 120) -> str:
        ttl_seconds = max(10, min(ttl_seconds, 300))
        token = secrets.token_urlsafe(32)
        self._records[job_id] = ExecutionTokenRecord(
            job_id=job_id,
            token_hash=hashlib.sha256(token.encode()).hexdigest(),
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds),
        )
        return token

    def consume(self, job_id: str, token: str) -> bool:
        record = self._records.get(job_id)
        if (
            not record
            or record.used
            or record.expires_at <= datetime.now(timezone.utc)
            or not secrets.compare_digest(
                record.token_hash, hashlib.sha256(token.encode()).hexdigest()
            )
        ):
            return False
        record.used = True
        return True

    def revoke(self, job_id: str) -> None:
        self._records.pop(job_id, None)


class RunnerCapabilities(BaseModel):
    generic_commands: bool = False
    host_mounts: bool = False
    docker_socket: bool = False
    application_credentials: bool = False
    network_mode: str = "restricted"
    controls: list[str] = Field(
        default_factory=lambda: [
            "read_only_root",
            "drop_all_capabilities",
            "no_new_privileges",
            "non_root",
            "job_scoped_token",
            "output_limits",
        ]
    )
