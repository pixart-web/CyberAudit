import pytest
from sqlalchemy import select

from cyberaudit import readiness_dlq
from cyberaudit.hardening_models import DeadLetterMessage
from cyberaudit.models import Organization


@pytest.mark.asyncio
async def test_capture_records_a_known_scenario(worker_session_factory, monkeypatch):
    monkeypatch.setattr(readiness_dlq, "SessionLocal", worker_session_factory)
    async with worker_session_factory() as db:
        organization = Organization(name="Readiness Tenant", slug="readiness-tenant")
        db.add(organization)
        await db.commit()
        organization_id = organization.id

    await readiness_dlq._capture(organization_id, "run-1", "invalid_message")

    async with worker_session_factory() as db:
        message = await db.scalar(
            select(DeadLetterMessage).where(
                DeadLetterMessage.organization_id == organization_id,
                DeadLetterMessage.message_id == "run-1-invalid_message",
            )
        )
    assert message is not None
    assert message.error_code == "INVALID_MESSAGE"
    assert message.queue_name == "connector_sync"
    assert message.schema_version == 1
    assert "synthetic-secret" not in message.error_summary


@pytest.mark.asyncio
async def test_capture_deduplicates_the_duplicate_message_scenario(
    worker_session_factory, monkeypatch
):
    monkeypatch.setattr(readiness_dlq, "SessionLocal", worker_session_factory)
    async with worker_session_factory() as db:
        organization = Organization(name="Dedup Tenant", slug="dedup-tenant")
        db.add(organization)
        await db.commit()
        organization_id = organization.id

    await readiness_dlq._capture(organization_id, "run-2", "duplicate_message")
    await readiness_dlq._capture(organization_id, "run-2", "duplicate_message")

    async with worker_session_factory() as db:
        message = await db.scalar(
            select(DeadLetterMessage).where(
                DeadLetterMessage.organization_id == organization_id,
                DeadLetterMessage.idempotency_key == "run-2-duplicate",
            )
        )
    assert message.attempts == 2


@pytest.mark.asyncio
async def test_capture_ignores_unknown_scenarios(worker_session_factory, monkeypatch):
    monkeypatch.setattr(readiness_dlq, "SessionLocal", worker_session_factory)
    # No organization is seeded: an unknown scenario must return before any
    # database access, so this would otherwise fail with a missing tenant.
    await readiness_dlq._capture("00000000-0000-0000-0000-000000000000", "run-3", "not-real")
