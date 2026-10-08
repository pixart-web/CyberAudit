"""The catalog must cover every permission the API enforces (no locked-out admins)."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cyberaudit.admin_api import ensure_rbac
from cyberaudit.models import Role, ScanProfile
from cyberaudit.provisioning import provision_assessment_catalog
from cyberaudit.rbac_catalog import ALL_PERMISSIONS, PLATFORM_PERMISSION, ROLE_DEFINITIONS
from cyberaudit.seed import ROLE_CODES
from cyberaudit.seed_phase3 import ROLE_PERMISSIONS

SRC = Path(__file__).resolve().parents[1] / "cyberaudit"


def test_every_enforced_permission_is_in_the_catalog():
    used: set[str] = set()
    for path in SRC.glob("*.py"):
        used |= set(re.findall(r'require_permission\(\s*"([a-z_.]+)"', path.read_text()))
    assert used - set(ALL_PERMISSIONS) == set()


def test_legacy_role_codes_exist_in_catalog():
    legacy = {c for codes in [*ROLE_CODES.values(), *ROLE_PERMISSIONS.values()] for c in codes}
    assert legacy - set(ALL_PERMISSIONS) == set()


def test_only_platform_role_has_platform_permission():
    holders = [n for n, c in ROLE_DEFINITIONS.items() if PLATFORM_PERMISSION in c]
    assert holders == ["Platform Administrator"]
    viewer = set(ROLE_DEFINITIONS["Read-only Viewer"])
    assert all(c.endswith(".read") for c in viewer)
    assert "users.manage" not in viewer and "audit_logs.read" not in viewer


@pytest.mark.asyncio
async def test_ensure_rbac_is_idempotent_and_administrator_covers_everything(db: AsyncSession):
    await ensure_rbac(db)
    await ensure_rbac(db)
    await db.commit()
    roles = {
        r.name: {p.code for p in r.permissions} for r in (await db.scalars(select(Role))).all()
    }
    assert roles["Administrator"] == set(ALL_PERMISSIONS) - {PLATFORM_PERMISSION}
    assert {
        "Auditor",
        "Reviewer",
        "Client",
        "Security Analyst",
        "Compliance Manager",
        "Read-only Viewer",
    } <= set(roles)


@pytest.mark.asyncio
async def test_catalog_provisioning_is_idempotent_and_excludes_demo_adapter(db: AsyncSession):
    from cyberaudit.models import Organization, User

    org = Organization(name="O", slug="o")
    db.add(org)
    await db.flush()
    user = User(
        organization_id=org.id,
        name="U",
        email="u@o.example.com",
        password_hash="not-a-real-hash",  # noqa: S106
    )
    db.add(user)
    await db.flush()
    first = await provision_assessment_catalog(db, org.id, user.id)
    assert first > 0
    assert await provision_assessment_catalog(db, org.id, user.id) == 0
    profiles = (await db.scalars(select(ScanProfile))).all()
    assert profiles and all(p.adapter_code != "cyberaudit.demo_assessment" for p in profiles)
