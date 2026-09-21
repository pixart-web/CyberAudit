"""Universal, tenant-scoped dead-letter handling."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cyberaudit.hardening_models import DeadLetterMessage
from cyberaudit.redaction import redact
from cyberaudit.rls import require_tenant_context

CRITICAL_QUEUES = frozenset(
    {
        "connector_sync",
        "graph_projection",
        "risk_recalculation",
        "event_processing",
        "detection",
        "incident_creation",
        "notifications",
        "reports",
        "exports",
        "retention",
        "backup",
        "restore",
        "ai_requests",
        "change_detection",
    }
)


class DeadLetterEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid")
    organization_id: str
    queue_name: str
    message_type: str = Field(pattern=r"^[a-z0-9_.-]{2,120}$")
    message_id: str = Field(min_length=8, max_length=160)
    idempotency_key: str = Field(min_length=8, max_length=160)
    payload_reference: str = Field(pattern=r"^(s3|azure|gcs|object)://[^\s]{8,990}$")
    schema_version: int = Field(default=1, ge=1, le=100)
    error_code: str = Field(pattern=r"^[A-Z0-9_]{2,120}$")
    error_summary: str = Field(min_length=2, max_length=500)


ReplayHandler = Callable[[DeadLetterMessage], Awaitable[None]]


class DeadLetterService:
    def __init__(
        self,
        handlers: dict[str, ReplayHandler] | None = None,
        *,
        supported_schema_versions: frozenset[int] = frozenset({1}),
    ) -> None:
        self.handlers = handlers or {}
        self.supported_schema_versions = supported_schema_versions

    async def capture(self, db: AsyncSession, envelope: DeadLetterEnvelope) -> DeadLetterMessage:
        await require_tenant_context(db, envelope.organization_id)
        if envelope.queue_name not in CRITICAL_QUEUES:
            raise ValueError("Queue is not registered for dead-letter handling")
        existing = await db.scalar(
            select(DeadLetterMessage).where(
                DeadLetterMessage.organization_id == envelope.organization_id,
                DeadLetterMessage.queue_name == envelope.queue_name,
                DeadLetterMessage.idempotency_key == envelope.idempotency_key,
            )
        )
        now = datetime.now(timezone.utc)
        if existing:
            existing.attempts += 1
            existing.last_failed_at = now
            existing.error_code = envelope.error_code
            existing.error_summary = str(redact(envelope.error_summary))
            existing.status = "pending"
            await db.flush()
            return existing
        message = DeadLetterMessage(
            organization_id=envelope.organization_id,
            queue_name=envelope.queue_name,
            message_type=envelope.message_type,
            message_id=envelope.message_id,
            idempotency_key=envelope.idempotency_key,
            payload_reference=envelope.payload_reference,
            schema_version=envelope.schema_version,
            error_code=envelope.error_code,
            error_summary=str(redact(envelope.error_summary)),
            first_failed_at=now,
            last_failed_at=now,
        )
        db.add(message)
        await db.flush()
        return message

    async def transition(
        self,
        db: AsyncSession,
        message: DeadLetterMessage,
        *,
        action: Literal["acknowledge", "replay", "discard"],
        actor_id: str,
        step_up_verified: bool,
        feature_enabled: bool = True,
    ) -> DeadLetterMessage:
        await require_tenant_context(db, message.organization_id)
        if action in {"replay", "discard"} and not step_up_verified:
            raise PermissionError("Phishing-resistant step-up is required")
        if message.status in {"discarded", "replayed"}:
            raise ValueError("Dead-letter message is already terminal")
        if action == "acknowledge":
            message.status = "acknowledged"
            message.acknowledged_by = actor_id
            message.acknowledged_at = datetime.now(timezone.utc)
        elif action == "discard":
            message.status = "discarded"
            message.acknowledged_by = actor_id
            message.acknowledged_at = datetime.now(timezone.utc)
        else:
            if not feature_enabled:
                raise PermissionError("Replay feature is disabled")
            if message.schema_version not in self.supported_schema_versions:
                raise ValueError("Dead-letter schema requires an explicit migration")
            handler = self.handlers.get(message.queue_name)
            if not handler:
                raise RuntimeError("No closed replay handler is registered")
            message.status = "replaying"
            await db.flush()
            try:
                await handler(message)
            except Exception:
                message.status = "pending"
                raise
            message.status = "replayed"
            message.replay_count += 1
        await db.flush()
        return message
