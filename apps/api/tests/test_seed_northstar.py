from __future__ import annotations

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from cyberaudit.models import Finding, Organization, User
from cyberaudit.seed_northstar import SLUG, seed_northstar


@pytest.mark.asyncio
async def test_northstar_seed_is_idempotent_labelled_and_isolated(db: AsyncSession):
    other = Organization(name="Real Customer", slug="real-customer")
    db.add(other)
    await db.commit()

    first = await seed_northstar(db, "Demo-Pass-For-Tests-1!")
    second = await seed_northstar(db, "Demo-Pass-For-Tests-1!")
    assert first == second

    findings = (await db.scalars(select(Finding).where(Finding.organization_id == first))).all()
    assert len(findings) >= 9
    assert all(
        f.simulated and f.verification_status == "unverified" and f.title.startswith("[DEMO]")
        for f in findings
    )
    assert (
        await db.scalar(
            select(func.count()).select_from(Finding).where(Finding.organization_id == other.id)
        )
        == 0
    )
    assert (
        await db.scalar(
            select(func.count()).select_from(User).where(User.organization_id == other.id)
        )
        == 0
    )
    emails = {
        e
        for (e,) in (
            await db.execute(select(User.email).where(User.organization_id == first))
        ).all()
    }
    assert all(e.endswith("@northstar-demo.example.com") for e in emails) and len(emails) == 3
    assert (await db.scalar(select(Organization).where(Organization.slug == SLUG))) is not None
