"""Transaction-scoped PostgreSQL tenant context.

The organization value is derived from the authenticated identity, never from
request input. PostgreSQL policies read the setting with `missing_ok=true` and
therefore deny when it is absent.
"""

from __future__ import annotations

import uuid

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from cyberaudit.observability import tenant_context_missing_total

RESOURCE_BOOTSTRAP_FUNCTIONS = {
    "scan_job": "cyberaudit_resolve_scan_job_organization",
    "connector_execution": "cyberaudit_resolve_connector_execution_organization",
    "security_event": "cyberaudit_resolve_security_event_organization",
}


def validate_organization_id(organization_id: str) -> str:
    try:
        return str(uuid.UUID(organization_id))
    except (ValueError, TypeError, AttributeError) as exc:
        raise ValueError("Invalid tenant context") from exc


async def set_tenant_context(db: AsyncSession, organization_id: str) -> None:
    normalized = validate_organization_id(organization_id)
    db.info["organization_id"] = normalized
    bind = db.get_bind()
    if bind.dialect.name == "postgresql":
        await db.execute(
            text("SELECT set_config('app.current_organization_id', :organization_id, true)"),
            {"organization_id": normalized},
        )


async def require_tenant_context(db: AsyncSession, organization_id: str) -> None:
    normalized = validate_organization_id(organization_id)
    if db.info.get("organization_id") != normalized:
        tenant_context_missing_total.inc()
        raise PermissionError("Tenant context is missing or mismatched")
    bind = db.get_bind()
    if bind.dialect.name == "postgresql":
        configured = await db.scalar(
            text("SELECT current_setting('app.current_organization_id', true)")
        )
        if configured != normalized:
            tenant_context_missing_total.inc()
            raise PermissionError("PostgreSQL tenant context is missing or mismatched")


async def clear_tenant_context(db: AsyncSession) -> None:
    db.info.pop("organization_id", None)
    bind = db.get_bind()
    if bind.dialect.name == "postgresql" and db.in_transaction():
        await db.execute(text("SELECT set_config('app.current_organization_id', '', true)"))


async def set_tenant_context_from_resource(
    db: AsyncSession, resource_type: str, resource_id: str
) -> str | None:
    function = RESOURCE_BOOTSTRAP_FUNCTIONS.get(resource_type)
    if not function:
        raise ValueError("Resource type cannot bootstrap tenant context")
    validate_organization_id(resource_id)
    if db.get_bind().dialect.name != "postgresql":
        return None
    organization_id = await db.scalar(
        text(f"SELECT {function}(:resource_id)"),
        {"resource_id": resource_id},
    )
    if not organization_id:
        return None
    normalized = validate_organization_id(str(organization_id))
    await set_tenant_context(db, normalized)
    return normalized
