"""REST API for the privacy-safe diagnostic bundle generator (10.4.1.x)."""

from __future__ import annotations

from dataclasses import asdict

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from cyberaudit.audit import write_audit
from cyberaudit.config import get_settings
from cyberaudit.db import get_db
from cyberaudit.diagnostics import build_diagnostic_bundle
from cyberaudit.models import User
from cyberaudit.security import require_permission

router = APIRouter(prefix="/api/v1/diagnostics", tags=["diagnostics"])


@router.get("/bundle")
async def get_diagnostic_bundle(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("diagnostics.export")),
):
    settings = get_settings()
    bundle = await build_diagnostic_bundle(db, settings, user)
    await write_audit(
        db,
        user,
        "diagnostics.bundle_generated",
        "diagnostic_bundle",
        None,
        metadata={"app_version": bundle.app_version},
    )
    await db.commit()
    return asdict(bundle)
