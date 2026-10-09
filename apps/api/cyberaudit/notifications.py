"""Persistent in-product notifications, created only by real state changes."""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from cyberaudit.phase4_models import Notification


def notify(
    db: AsyncSession,
    *,
    organization_id: str,
    user_id: str | None,
    event_type: str,
    severity: str,
    title: str,
    message: str,
    resource_type: str | None = None,
    resource_id: str | None = None,
) -> None:
    """Queue a notification in the caller's transaction (no commit here).

    ``user_id=None`` means every user of the organization. Messages must not contain
    secrets or personal data; callers pass already-sanitised text.
    """
    db.add(
        Notification(
            organization_id=organization_id,
            user_id=user_id,
            event_type=event_type,
            severity=severity,
            title=title[:240],
            message=message[:2000],
            resource_type=resource_type,
            resource_id=resource_id,
        )
    )
