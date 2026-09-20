"""Sovereign AI runtime: the local model registry.

A manifest row describes a model that CyberAudit *may* use for a given
capability on this installation. It is deliberately host-scoped rather than
tenant-scoped (no ``organization_id``): the underlying model weights live
once on the host's disk and are shared by every tenant of that installation,
the same way the API process or the Redis broker are shared infrastructure
rather than customer data. Access is gated by the ``ai_runtime.read`` /
``ai_runtime.manage`` permissions instead of tenant RLS.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from cyberaudit.db import Base
from cyberaudit.enterprise_models import utcnow, uuid4


class AiModelManifest(Base):
    __tablename__ = "ai_model_manifests"
    __table_args__ = (UniqueConstraint("model_id", "version", "quantization"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid4)
    model_id: Mapped[str] = mapped_column(String(160), index=True)
    family: Mapped[str] = mapped_column(String(40), index=True)
    version: Mapped[str] = mapped_column(String(40))
    quantization: Mapped[str] = mapped_column(String(30))
    size_gb: Mapped[float] = mapped_column(Float)
    context_window: Mapped[int] = mapped_column(Integer)
    capabilities: Mapped[list[str]] = mapped_column(JSON, default=list)
    ram_required_mb: Mapped[int] = mapped_column(Integer)
    vram_required_mb: Mapped[int] = mapped_column(Integer, default=0)
    cpu_compatible: Mapped[bool] = mapped_column(Boolean, default=True)
    gpu_compatible: Mapped[bool] = mapped_column(Boolean, default=False)
    license: Mapped[str] = mapped_column(String(120))
    source: Mapped[str] = mapped_column(String(500))
    sha256: Mapped[str | None] = mapped_column(String(64))
    manifest_signature: Mapped[str | None] = mapped_column(String(1024))
    install_status: Mapped[str] = mapped_column(String(30), default="not_installed")
    trust_status: Mapped[str] = mapped_column(String(30), default="unverified")
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    registered_by: Mapped[str | None] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )
