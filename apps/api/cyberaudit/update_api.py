"""REST API for offline/air-gapped update bundle validation (10.3.7).

Validation only: this never stages, extracts or applies a bundle. See
:mod:`cyberaudit.update_bundle` for why, and ADR-029 for what remains
architecture-only in this phase.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import asdict

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.ext.asyncio import AsyncSession

from cyberaudit.audit import write_audit
from cyberaudit.config import get_settings
from cyberaudit.db import get_db
from cyberaudit.models import User
from cyberaudit.security import require_permission
from cyberaudit.update_bundle import TrustedKeyStore, UpdateBundleService

router = APIRouter(prefix="/api/v1/updates", tags=["updates"])


class BundleFile(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=255)
    content_base64: str


class BundleValidateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    manifest_json: str = Field(min_length=2, max_length=200_000)
    signature_base64: str
    files: list[BundleFile] = Field(default_factory=list, max_length=200)


@router.post("/validate")
async def validate_bundle(
    payload: BundleValidateRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("updates.read")),
):
    settings = get_settings()
    if not settings.update_trusted_public_keys_pem:
        raise HTTPException(
            409, "No trusted signing keys are configured; every bundle would be rejected"
        )
    try:
        trusted_keys = TrustedKeyStore(
            [pem.encode() for pem in settings.update_trusted_public_keys_pem]
        )
        signature = base64.b64decode(payload.signature_base64, validate=True)
        files = {
            item.name: base64.b64decode(item.content_base64, validate=True)
            for item in payload.files
        }
    except (ValueError, binascii.Error) as exc:
        raise HTTPException(422, f"Malformed request: {exc}") from exc

    service = UpdateBundleService(trusted_keys, current_app_version=settings.app_version)
    result = service.validate(payload.manifest_json.encode(), signature, files)
    await write_audit(
        db,
        user,
        "update_bundle.validated",
        "update_bundle",
        result.bundle_id,
        result="success" if result.accepted else "denied",
        metadata={"bundle_type": result.bundle_type, "reasons": result.reasons},
    )
    await db.commit()
    return asdict(result)
