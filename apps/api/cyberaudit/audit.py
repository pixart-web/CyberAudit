from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from cyberaudit.models import AuditLog, User

SENSITIVE_KEYS = {"password", "password_hash", "token", "access_token", "refresh_token", "secret"}


def sanitize_metadata(value: dict[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if key.lower() not in SENSITIVE_KEYS}


async def write_audit(
    db: AsyncSession,
    user: User,
    action: str,
    resource_type: str,
    resource_id: str | None,
    result: str = "success",
    metadata: dict[str, Any] | None = None,
) -> None:
    db.add(
        AuditLog(
            organization_id=user.organization_id,
            actor_id=user.id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            result=result,
            event_metadata=sanitize_metadata(metadata or {}),
        )
    )
