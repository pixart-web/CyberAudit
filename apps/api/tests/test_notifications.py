"""Notifications come only from real state changes and stay tenant/user scoped."""

from __future__ import annotations

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cyberaudit.models import (
    Intensity,
    JobStatus,
    Organization,
    ScanJob,
    TargetType,
    User,
)
from cyberaudit.notifications import notify
from cyberaudit.orchestrator import transition_job
from cyberaudit.phase4_models import Notification


async def _job(db: AsyncSession, status: JobStatus) -> tuple[ScanJob, User]:
    org = Organization(name="O", slug=f"o-{status.value}")
    db.add(org)
    await db.flush()
    user = User(
        organization_id=org.id,
        name="U",
        email=f"u-{status.value}@o.example.com",
        password_hash="not-a-real-hash",  # noqa: S106
    )
    db.add(user)
    await db.flush()
    job = ScanJob(
        organization_id=org.id,
        engagement_id="e",
        scope_id="s",
        scan_profile_id="p",
        adapter_code="a",
        target_type=TargetType.IP,
        target_value="10.0.0.1",
        normalized_target="10.0.0.1",
        technique="t",
        intensity=Intensity.LOW,
        status=status,
        requested_by=user.id,
    )
    db.add(job)
    await db.flush()
    return job, user


@pytest.mark.asyncio
async def test_terminal_job_states_notify_the_requester_only(db: AsyncSession):
    done, u1 = await _job(db, JobStatus.PROCESSING_RESULTS)
    failed, u2 = await _job(db, JobStatus.RUNNING)
    await transition_job(db, done, JobStatus.COMPLETED, "ok")
    await transition_job(db, failed, JobStatus.FAILED, "adapter error")
    await db.commit()
    rows = {n.user_id: n for n in (await db.scalars(select(Notification))).all()}
    assert rows[u1.id].event_type == "job.completed" and rows[u1.id].resource_id == done.id
    assert rows[u2.id].event_type == "job.failed" and rows[u2.id].severity == "error"
    assert rows[u1.id].organization_id != rows[u2.id].organization_id


@pytest.mark.asyncio
async def test_non_terminal_transitions_do_not_notify(db: AsyncSession):
    job, _ = await _job(db, JobStatus.QUEUED)
    await transition_job(db, job, JobStatus.STARTING, "starting")
    await db.commit()
    assert (await db.scalars(select(Notification))).all() == []


@pytest.mark.asyncio
async def test_notify_truncates_and_defaults_unread(db: AsyncSession):
    job, user = await _job(db, JobStatus.QUEUED)
    notify(
        db,
        organization_id=job.organization_id,
        user_id=user.id,
        event_type="x",
        severity="info",
        title="t" * 500,
        message="m" * 5000,
    )
    await db.commit()
    row = (await db.scalars(select(Notification))).one()
    assert len(row.title) == 240 and len(row.message) == 2000 and row.read_at is None
