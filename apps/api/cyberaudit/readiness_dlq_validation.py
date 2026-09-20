"""Drive and verify real Redis/worker dead-letter scenarios."""

from __future__ import annotations

import asyncio
import json
import sys
from uuid import uuid4

from sqlalchemy import select

from cyberaudit.db import SessionLocal
from cyberaudit.dead_letter import DeadLetterService
from cyberaudit.hardening_models import DeadLetterMessage
from cyberaudit.models import User
from cyberaudit.readiness_dlq import SCENARIOS, capture_readiness_dead_letter
from cyberaudit.rls import set_tenant_context


async def validate(organization_id: str) -> dict[str, object]:
    run_id = f"readiness-{uuid4().hex[:12]}"
    scenarios = list(SCENARIOS)
    for scenario in scenarios:
        capture_readiness_dead_letter.send(organization_id, run_id, scenario)

    rows: list[DeadLetterMessage] = []
    for _ in range(60):
        async with SessionLocal() as db:
            await set_tenant_context(db, organization_id)
            rows = list(
                (
                    await db.scalars(
                        select(DeadLetterMessage).where(
                            DeadLetterMessage.organization_id == organization_id,
                            DeadLetterMessage.message_id.like(f"{run_id}%"),
                        )
                    )
                ).all()
            )
        if len(rows) == len(scenarios):
            break
        await asyncio.sleep(0.5)
    if len(rows) != len(scenarios):
        raise RuntimeError("Timed out waiting for real worker DLQ messages")

    capture_readiness_dead_letter.send(organization_id, run_id, "duplicate_message")
    duplicate_ready = False
    for _ in range(30):
        async with SessionLocal() as db:
            await set_tenant_context(db, organization_id)
            duplicate_attempts = await db.scalar(
                select(DeadLetterMessage.attempts).where(
                    DeadLetterMessage.organization_id == organization_id,
                    DeadLetterMessage.idempotency_key == f"{run_id}-duplicate",
                )
            )
        if duplicate_attempts == 2:
            duplicate_ready = True
            break
        await asyncio.sleep(0.25)
    if not duplicate_ready:
        raise RuntimeError("Timed out waiting for duplicate DLQ handling")

    async with SessionLocal() as db:
        await set_tenant_context(db, organization_id)
        rows = list(
            (
                await db.scalars(
                    select(DeadLetterMessage).where(
                        DeadLetterMessage.organization_id == organization_id,
                        DeadLetterMessage.message_id.like(f"{run_id}%"),
                    )
                )
            ).all()
        )
        actor_id = await db.scalar(select(User.id).where(User.organization_id == organization_id))
        if not actor_id:
            raise RuntimeError("Synthetic readiness actor is missing")
        replayed: list[str] = []

        async def replay_handler(message: DeadLetterMessage) -> None:
            replayed.append(message.message_type)

        replay_target = next(row for row in rows if row.error_code == "PROVIDER_TIMEOUT")
        await DeadLetterService({"connector_sync": replay_handler}).transition(
            db,
            replay_target,
            action="replay",
            actor_id=actor_id,
            step_up_verified=True,
        )
        discard_target = next(row for row in rows if row.error_code == "POISON_MESSAGE")
        await DeadLetterService().transition(
            db,
            discard_target,
            action="discard",
            actor_id=actor_id,
            step_up_verified=True,
        )
        old_schema = next(row for row in rows if row.schema_version == 99)
        old_schema_denied = False
        try:
            await DeadLetterService({"connector_sync": replay_handler}).transition(
                db,
                old_schema,
                action="replay",
                actor_id=actor_id,
                step_up_verified=True,
            )
        except ValueError:
            old_schema_denied = True
        await db.commit()

    duplicate = next(row for row in rows if row.error_code == "DUPLICATE_MESSAGE")
    secrets_absent = all(
        "synthetic-secret" not in row.error_summary
        and row.payload_reference.startswith("object://")
        for row in rows
    )
    return {
        "status": "passed",
        "synthetic_data_only": True,
        "redis_queue": "cyberaudit.readiness.dlq",
        "worker_processed": len(rows),
        "scenarios": scenarios,
        "duplicate_deduplicated": duplicate.attempts == 2,
        "replay_completed": bool(replayed),
        "discard_completed": discard_target.status == "discarded",
        "old_schema_replay_denied": old_schema_denied,
        "secrets_absent": secrets_absent,
        "tenant_scoped": all(row.organization_id == organization_id for row in rows),
    }


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("organization id is required")
    print(json.dumps(asyncio.run(validate(sys.argv[1])), sort_keys=True))


if __name__ == "__main__":
    main()
