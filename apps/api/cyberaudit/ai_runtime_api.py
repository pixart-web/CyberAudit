"""REST API for the sovereign, local-first AI runtime (Phase 10.3)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import inspect
from sqlalchemy.ext.asyncio import AsyncSession

from cyberaudit.ai_runtime import (
    CapabilityRouter,
    HardwareCapabilityService,
    ModelRegistryService,
    build_inference_backend,
)
from cyberaudit.audit import write_audit
from cyberaudit.config import get_settings
from cyberaudit.db import get_db
from cyberaudit.models import User
from cyberaudit.security import require_permission

router = APIRouter(prefix="/api/v1/ai-runtime", tags=["ai-runtime"])


def _serialize(record: Any) -> dict[str, Any]:
    return {
        attribute.key: getattr(record, attribute.key)
        for attribute in inspect(record).mapper.column_attrs
    }


class ModelManifestCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    model_id: str = Field(min_length=2, max_length=160)
    family: str
    version: str = Field(min_length=1, max_length=40)
    quantization: str = Field(min_length=1, max_length=30)
    size_gb: float = Field(gt=0, le=1024)
    context_window: int = Field(gt=0, le=2_000_000)
    capabilities: list[str] = Field(min_length=1, max_length=20)
    ram_required_mb: int = Field(gt=0)
    vram_required_mb: int = Field(default=0, ge=0)
    cpu_compatible: bool = True
    gpu_compatible: bool = False
    license: str = Field(min_length=1, max_length=120)
    source: str = Field(min_length=1, max_length=500)
    sha256: str | None = Field(default=None, min_length=64, max_length=64)


@router.get("/hardware")
async def hardware_capabilities(
    user: User = Depends(require_permission("ai_runtime.read")),
):
    capabilities = HardwareCapabilityService.detect()
    profile = HardwareCapabilityService.classify(capabilities)
    return {
        "os_name": capabilities.os_name,
        "architecture": capabilities.architecture,
        "cpu_model": capabilities.cpu_model,
        "cpu_cores": capabilities.cpu_cores,
        "ram_total_mb": capabilities.ram_total_mb,
        "ram_available_mb": capabilities.ram_available_mb,
        "disk_total_gb": capabilities.disk_total_gb,
        "disk_free_gb": capabilities.disk_free_gb,
        "gpu_vendor": capabilities.gpu_vendor,
        "gpu_model": capabilities.gpu_model,
        "vram_mb": capabilities.vram_mb,
        "accelerations": capabilities.accelerations,
        "profile": profile.value,
    }


@router.get("/health")
async def runtime_health(
    user: User = Depends(require_permission("ai_runtime.read")),
):
    settings = get_settings()
    backend = build_inference_backend(settings)
    health = await backend.health_check()
    return {
        "backend": health.backend,
        "healthy": health.healthy,
        "message": health.message,
        "checked_at": health.checked_at,
        "sovereign_default": settings.ai_runtime_backend == "disabled",
    }


@router.get("/models")
async def list_models(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("ai_runtime.read")),
):
    models = await ModelRegistryService(db).list_models()
    return {"items": [_serialize(model) for model in models]}


@router.post("/models", status_code=201)
async def register_model(
    payload: ModelManifestCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("ai_runtime.manage")),
):
    try:
        manifest = await ModelRegistryService(db).register(
            registered_by=user.id, **payload.model_dump()
        )
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    await write_audit(
        db,
        user,
        "ai_runtime.model_registered",
        "ai_model_manifest",
        manifest.id,
        metadata={"model_id": manifest.model_id, "family": manifest.family},
    )
    await db.commit()
    return _serialize(manifest)


class InstallStatusUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: str


@router.post("/models/{manifest_id}/install-status")
async def update_install_status(
    manifest_id: str,
    payload: InstallStatusUpdate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("ai_runtime.manage")),
):
    try:
        manifest = await ModelRegistryService(db).mark_install_status(manifest_id, payload.status)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc
    await write_audit(
        db,
        user,
        "ai_runtime.model_install_status_updated",
        "ai_model_manifest",
        manifest.id,
        metadata={"status": manifest.install_status},
    )
    await db.commit()
    return _serialize(manifest)


@router.get("/capabilities/{capability}")
async def resolve_capability(
    capability: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("ai_runtime.read")),
):
    models = await ModelRegistryService(db).list_models()
    hardware = HardwareCapabilityService.detect()
    resolved = CapabilityRouter(models, hardware).resolve(capability)
    if resolved is None:
        return {"capability": capability, "available": False, "model": None}
    return {
        "capability": capability,
        "available": True,
        "model": {
            "model_id": resolved.model_id,
            "family": resolved.family,
            "version": resolved.version,
        },
    }
