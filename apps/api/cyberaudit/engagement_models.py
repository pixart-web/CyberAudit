"""Engagement domain completion (Phase 10.3.6) and reporting (10.3.38).

Client -> Engagement -> Scope/Assets/Evidence/Findings already exist in
``cyberaudit.models``. This module adds the remaining first-class concepts
called for by the engagement domain: structured, authored notes, a
timeline of engagement-level events, and generated reports.

Reports must distinguish observed evidence and deterministic findings from
analyst conclusions and AI-generated explanations (see ADR-024 and
ADR-026): ``ReportSection.content_type`` records which one a section is,
and AI-generated sections always carry the citations that grounded them.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from cyberaudit.db import Base
from cyberaudit.enterprise_models import utcnow, uuid4


class EngagementNote(Base):
    __tablename__ = "engagement_notes"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid4)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    engagement_id: Mapped[str] = mapped_column(ForeignKey("engagements.id"), index=True)
    author_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    body: Mapped[str] = mapped_column(Text)
    pinned: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class EngagementTimelineEntry(Base):
    __tablename__ = "engagement_timeline_entries"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid4)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    engagement_id: Mapped[str] = mapped_column(ForeignKey("engagements.id"), index=True)
    actor_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"))
    event_type: Mapped[str] = mapped_column(String(80), index=True)
    summary: Mapped[str] = mapped_column(String(500))
    event_metadata: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid4)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    engagement_id: Mapped[str] = mapped_column(ForeignKey("engagements.id"), index=True)
    report_type: Mapped[str] = mapped_column(String(40), default="technical_findings")
    title: Mapped[str] = mapped_column(String(300))
    status: Mapped[str] = mapped_column(String(30), default="draft")
    generated_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class ReportSection(Base):
    __tablename__ = "report_sections"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid4)
    report_id: Mapped[str] = mapped_column(ForeignKey("reports.id"), index=True)
    position: Mapped[int] = mapped_column(default=0)
    heading: Mapped[str] = mapped_column(String(300))
    # "evidence" | "finding" | "analyst_conclusion" | "ai_generated"
    content_type: Mapped[str] = mapped_column(String(30))
    body: Mapped[str] = mapped_column(Text)
    source_references: Mapped[list[str]] = mapped_column(JSON, default=list)
    ai_citations: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
