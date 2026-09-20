"""REST API for engagement notes, timeline and reports (10.3.6 / section 38)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import inspect, select
from sqlalchemy.ext.asyncio import AsyncSession

from cyberaudit.audit import write_audit
from cyberaudit.db import get_db
from cyberaudit.engagement_models import (
    EngagementNote,
    EngagementTimelineEntry,
    Report,
    ReportSection,
)
from cyberaudit.engagement_services import (
    EngagementNotFoundError,
    ReportService,
    record_timeline_event,
)
from cyberaudit.models import User
from cyberaudit.security import require_permission

router = APIRouter(prefix="/api/v1/engagements", tags=["engagement-domain"])
reports_router = APIRouter(prefix="/api/v1/reports", tags=["engagement-domain"])


def _serialize(record: Any) -> dict[str, Any]:
    return {
        attribute.key: getattr(record, attribute.key)
        for attribute in inspect(record).mapper.column_attrs
    }


class NoteCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    body: str = Field(min_length=1, max_length=10_000)
    pinned: bool = False


@router.post("/{engagement_id}/notes", status_code=201)
async def create_note(
    engagement_id: str,
    payload: NoteCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("engagements.manage")),
):
    note = EngagementNote(
        organization_id=user.organization_id,
        engagement_id=engagement_id,
        author_id=user.id,
        body=payload.body,
        pinned=payload.pinned,
    )
    db.add(note)
    await write_audit(db, user, "engagement.note_created", "engagement_note", note.id)
    await db.commit()
    return _serialize(note)


@router.get("/{engagement_id}/notes")
async def list_notes(
    engagement_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("engagements.read")),
):
    rows = list(
        (
            await db.scalars(
                select(EngagementNote)
                .where(
                    EngagementNote.organization_id == user.organization_id,
                    EngagementNote.engagement_id == engagement_id,
                )
                .order_by(EngagementNote.pinned.desc(), EngagementNote.created_at.desc())
            )
        ).all()
    )
    return {"items": [_serialize(row) for row in rows]}


@router.get("/{engagement_id}/timeline")
async def list_timeline(
    engagement_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("engagements.read")),
):
    rows = list(
        (
            await db.scalars(
                select(EngagementTimelineEntry)
                .where(
                    EngagementTimelineEntry.organization_id == user.organization_id,
                    EngagementTimelineEntry.engagement_id == engagement_id,
                )
                .order_by(EngagementTimelineEntry.occurred_at.desc())
            )
        ).all()
    )
    return {"items": [_serialize(row) for row in rows]}


class TimelineEventCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    event_type: str = Field(min_length=2, max_length=80)
    summary: str = Field(min_length=1, max_length=500)
    metadata: dict[str, Any] = Field(default_factory=dict)


@router.post("/{engagement_id}/timeline", status_code=201)
async def create_timeline_event(
    engagement_id: str,
    payload: TimelineEventCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("engagements.manage")),
):
    try:
        entry = await record_timeline_event(
            db,
            user.organization_id,
            engagement_id,
            actor_id=user.id,
            event_type=payload.event_type,
            summary=payload.summary,
            metadata=payload.metadata,
        )
    except EngagementNotFoundError as exc:
        raise HTTPException(404, str(exc)) from exc
    await db.commit()
    return _serialize(entry)


class ReportGenerateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    report_type: str = "technical_findings"
    include_ai_summary: bool = False


@router.post("/{engagement_id}/reports", status_code=201)
async def generate_report(
    engagement_id: str,
    payload: ReportGenerateRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("reports.manage")),
):
    try:
        report = await ReportService(db).generate(
            user.organization_id,
            engagement_id,
            user,
            report_type=payload.report_type,
            include_ai_summary=payload.include_ai_summary,
        )
    except EngagementNotFoundError as exc:
        await db.rollback()
        raise HTTPException(404, str(exc)) from exc
    except ValueError as exc:
        await db.rollback()
        raise HTTPException(422, str(exc)) from exc
    await write_audit(
        db, user, "report.generated", "report", report.id, metadata={"type": report.report_type}
    )
    await db.commit()
    return _serialize(report)


@router.get("/{engagement_id}/reports")
async def list_reports(
    engagement_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("reports.read")),
):
    rows = list(
        (
            await db.scalars(
                select(Report)
                .where(
                    Report.organization_id == user.organization_id,
                    Report.engagement_id == engagement_id,
                )
                .order_by(Report.created_at.desc())
            )
        ).all()
    )
    return {"items": [_serialize(row) for row in rows]}


@reports_router.get("/{report_id}")
async def get_report(
    report_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("reports.read")),
):
    report = await db.get(Report, report_id)
    if not report or report.organization_id != user.organization_id:
        raise HTTPException(404, "Report not found")
    sections = list(
        (
            await db.scalars(
                select(ReportSection)
                .where(ReportSection.report_id == report.id)
                .order_by(ReportSection.position)
            )
        ).all()
    )
    return {
        "report": _serialize(report),
        "sections": [_serialize(section) for section in sections],
    }
