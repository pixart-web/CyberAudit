"""Idempotent provisioning of the built-in, safe assessment catalog for a tenant."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cyberaudit.adapters import AdapterRegistry
from cyberaudit.models import Intensity, ScanProfile, ToolAdapterDefinition
from cyberaudit.seed_phase3 import PROFILE_DATA


async def provision_assessment_catalog(
    db: AsyncSession, organization_id: str, created_by: str
) -> int:
    """Register built-in adapters (global) and the tenant's default scan profiles.

    Only the safe, constrained adapters of the existing registry are used; the
    demo-only adapter is never provisioned. Returns the number of profiles added.
    """
    registry = AdapterRegistry()
    for metadata in registry.metadata():
        if metadata.code == "cyberaudit.demo_assessment":
            continue
        if await db.scalar(
            select(ToolAdapterDefinition).where(ToolAdapterDefinition.code == metadata.code)
        ):
            continue
        db.add(
            ToolAdapterDefinition(
                code=metadata.code,
                name=metadata.name,
                version=metadata.version,
                category=metadata.category,
                description=metadata.description,
                supported_target_types=[t.value for t in metadata.supported_target_types],
                supported_intensities=[i.value for i in metadata.supported_intensities],
                requires_network=metadata.requires_network,
                requires_approval=False,
                default_timeout=metadata.default_timeout,
                enabled=True,
                health_status="online",
                adapter_metadata={
                    "phase": 3,
                    "safe": True,
                    "configuration_schema": metadata.configuration_schema,
                },
            )
        )
    added = 0
    for (
        name,
        category,
        adapter_code,
        target_types,
        intensity,
        timeout,
        configuration,
        impact,
    ) in PROFILE_DATA:
        if await db.scalar(
            select(ScanProfile).where(
                ScanProfile.organization_id == organization_id, ScanProfile.name == name
            )
        ):
            continue
        metadata = registry.get(adapter_code).metadata()
        db.add(
            ScanProfile(
                organization_id=organization_id,
                name=name,
                description=f"{metadata.description} Impacto: {impact}",
                category=category,
                adapter_code=adapter_code,
                target_types=[item.value for item in target_types],
                default_intensity=intensity,
                maximum_intensity=Intensity.LOW,
                timeout_seconds=timeout,
                cpu_limit=0.5,
                memory_limit_mb=256,
                network_access=metadata.requires_network,
                requires_approval=False,
                enabled=True,
                configuration_schema=metadata.configuration_schema,
                default_configuration=configuration,
                created_by=created_by,
            )
        )
        added += 1
    await db.flush()
    return added
