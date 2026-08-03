"""Synthetic Redis-worker DLQ scenarios for infrastructure readiness."""

from __future__ import annotations

import asyncio

import dramatiq

from cyberaudit.db import SessionLocal
from cyberaudit.dead_letter import DeadLetterEnvelope, DeadLetterService
from cyberaudit.queue import broker as _configured_broker  # noqa: F401
from cyberaudit.rls import set_tenant_context

SCENARIOS = {
    "invalid_message": ("INVALID_MESSAGE", 1),
    "timeout": ("PROVIDER_TIMEOUT", 1),
    "permanent_error": ("PERMANENT_ERROR", 1),
    "poison_message": ("POISON_MESSAGE", 1),
    "duplicate_message": ("DUPLICATE_MESSAGE", 1),
    "old_schema": ("SCHEMA_UNSUPPORTED", 99),
    "invalid_tenant": ("TENANT_INVALID", 1),
    "authorization_expired": ("AUTHORIZATION_EXPIRED", 1),
    "worker_failure": ("WORKER_FAILURE", 1),
}


@dramatiq.actor(queue_name="cyberaudit.readiness.dlq", max_retries=0, time_limit=30_000)
def capture_readiness_dead_letter(organization_id: str, run_id: str, scenario: str) -> None:
    asyncio.run(_capture(organization_id, run_id, scenario))


async def _capture(organization_id: str, run_id: str, scenario: str) -> None:
    if scenario not in SCENARIOS:
        return
    error_code, schema_version = SCENARIOS[scenario]
    idempotency_scenario = "duplicate" if scenario == "duplicate_message" else scenario
    async with SessionLocal() as db:
        await set_tenant_context(db, organization_id)
        await DeadLetterService().capture(
            db,
            DeadLetterEnvelope(
                organization_id=organization_id,
                queue_name="connector_sync",
                message_type=f"readiness.{scenario}",
                message_id=f"{run_id}-{scenario}",
                idempotency_key=f"{run_id}-{idempotency_scenario}",
                payload_reference=f"object://readiness/{run_id}/{scenario}",
                schema_version=schema_version,
                error_code=error_code,
                error_summary=f"Synthetic {scenario}; token=synthetic-secret",
            ),
        )
        await db.commit()
