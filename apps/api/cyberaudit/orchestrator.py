from datetime import datetime, timedelta, timezone
from typing import Any, Protocol

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cyberaudit.adapters import AdapterRegistry, NormalizedTarget
from cyberaudit.audit import write_audit
from cyberaudit.execution_schemas import JobCreate
from cyberaudit.models import (
    Approval,
    ApprovalStatus,
    Asset,
    Engagement,
    EventType,
    Intensity,
    JobEvent,
    JobStatus,
    ScanJob,
    ScanProfile,
    Scope,
    ToolAdapterDefinition,
    User,
    utcnow,
)
from cyberaudit.observability import approvals, jobs_created, policy_denials, structured_event
from cyberaudit.policy import INTENSITY_ORDER, ScopePolicyEngine, normalized_target
from cyberaudit.schemas import PolicyRequest


class QueuePublisher(Protocol):
    def __call__(self, job_id: str) -> None: ...


TRANSITIONS: dict[JobStatus, set[JobStatus]] = {
    JobStatus.DRAFT: {JobStatus.PENDING_POLICY},
    JobStatus.PENDING_POLICY: {JobStatus.DENIED, JobStatus.PENDING_APPROVAL, JobStatus.QUEUED},
    JobStatus.PENDING_APPROVAL: {JobStatus.APPROVED, JobStatus.DENIED, JobStatus.CANCELLED},
    JobStatus.APPROVED: {JobStatus.QUEUED},
    JobStatus.QUEUED: {JobStatus.STARTING, JobStatus.CANCELLING},
    JobStatus.STARTING: {
        JobStatus.RUNNING,
        JobStatus.FAILED,
        JobStatus.TIMED_OUT,
        JobStatus.CANCELLING,
    },
    JobStatus.RUNNING: {
        JobStatus.PROCESSING_RESULTS,
        JobStatus.FAILED,
        JobStatus.TIMED_OUT,
        JobStatus.CANCELLING,
    },
    JobStatus.PROCESSING_RESULTS: {
        JobStatus.COMPLETED,
        JobStatus.COMPLETED_WITH_WARNINGS,
        JobStatus.FAILED,
    },
    JobStatus.CANCELLING: {JobStatus.CANCELLED, JobStatus.FAILED},
    JobStatus.DENIED: set(),
    JobStatus.COMPLETED: set(),
    JobStatus.COMPLETED_WITH_WARNINGS: set(),
    JobStatus.FAILED: set(),
    JobStatus.TIMED_OUT: set(),
    JobStatus.CANCELLED: set(),
}

EVENT_FOR_STATUS = {
    JobStatus.PENDING_POLICY: EventType.POLICY_EVALUATED,
    JobStatus.DENIED: EventType.FAILED,
    JobStatus.PENDING_APPROVAL: EventType.APPROVAL_REQUESTED,
    JobStatus.APPROVED: EventType.APPROVED,
    JobStatus.QUEUED: EventType.QUEUED,
    JobStatus.STARTING: EventType.WORKER_ASSIGNED,
    JobStatus.RUNNING: EventType.STARTED,
    JobStatus.PROCESSING_RESULTS: EventType.OUTPUT_RECEIVED,
    JobStatus.COMPLETED: EventType.COMPLETED,
    JobStatus.COMPLETED_WITH_WARNINGS: EventType.WARNING,
    JobStatus.FAILED: EventType.FAILED,
    JobStatus.TIMED_OUT: EventType.TIMEOUT,
    JobStatus.CANCELLING: EventType.CANCELLATION_REQUESTED,
    JobStatus.CANCELLED: EventType.CANCELLED,
}


class InvalidJobTransition(ValueError):
    pass


def approval_is_expired(expires_at: datetime) -> bool:
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    return expires_at <= datetime.now(timezone.utc)


async def transition_job(
    db: AsyncSession,
    job: ScanJob,
    new_status: JobStatus,
    message: str,
    metadata: dict[str, Any] | None = None,
    actor: User | None = None,
) -> None:
    if new_status not in TRANSITIONS[job.status]:
        raise InvalidJobTransition(
            f"Invalid job transition: {job.status.value} -> {new_status.value}"
        )
    previous = job.status
    job.status = new_status
    job.status_message = message[:500]
    now = utcnow()
    if new_status == JobStatus.QUEUED:
        job.queued_at = now
    elif new_status == JobStatus.RUNNING:
        job.started_at = now
    elif new_status in {
        JobStatus.COMPLETED,
        JobStatus.COMPLETED_WITH_WARNINGS,
        JobStatus.FAILED,
        JobStatus.TIMED_OUT,
    }:
        job.completed_at = now
    elif new_status == JobStatus.CANCELLED:
        job.cancelled_at = now
    db.add(
        JobEvent(
            organization_id=job.organization_id,
            job_id=job.id,
            event_type=EVENT_FOR_STATUS[new_status],
            severity="error" if new_status in {JobStatus.DENIED, JobStatus.FAILED} else "info",
            message=message,
            event_metadata={"from": previous.value, "to": new_status.value, **(metadata or {})},
        )
    )
    if actor:
        await write_audit(
            db,
            actor,
            "job.status_changed",
            "scan_job",
            job.id,
            "success",
            {"from": previous.value, "to": new_status.value},
        )


async def update_progress(
    db: AsyncSession,
    job: ScanJob,
    progress: int,
    message: str,
) -> None:
    if not 0 <= progress <= 100:
        raise ValueError("Progress must be between 0 and 100")
    if progress < job.progress:
        raise ValueError("Progress cannot decrease")
    if progress == job.progress:
        return
    job.progress = progress
    job.status_message = message[:500]
    db.add(
        JobEvent(
            organization_id=job.organization_id,
            job_id=job.id,
            event_type=EventType.PROGRESS,
            severity="info",
            message=message,
            event_metadata={"progress": progress},
        )
    )


class JobOrchestrator:
    def __init__(
        self,
        policy_engine: ScopePolicyEngine,
        registry: AdapterRegistry,
        enqueue: QueuePublisher,
    ) -> None:
        self.policy_engine = policy_engine
        self.registry = registry
        self.enqueue = enqueue

    async def create_job(
        self,
        db: AsyncSession,
        user: User,
        payload: JobCreate,
    ) -> ScanJob:
        engagement = await db.scalar(
            select(Engagement).where(
                Engagement.id == payload.engagement_id,
                Engagement.organization_id == user.organization_id,
                Engagement.deleted_at.is_(None),
            )
        )
        scope = await db.scalar(
            select(Scope).where(
                Scope.id == payload.scope_id,
                Scope.organization_id == user.organization_id,
                Scope.engagement_id == payload.engagement_id,
                Scope.deleted_at.is_(None),
            )
        )
        profile = await db.scalar(
            select(ScanProfile).where(
                ScanProfile.id == payload.scan_profile_id,
                ScanProfile.organization_id == user.organization_id,
                ScanProfile.enabled.is_(True),
                ScanProfile.deleted_at.is_(None),
            )
        )
        if not engagement or not scope or not profile:
            raise ValueError("Engagement, scope or enabled profile not found")
        definition = await db.scalar(
            select(ToolAdapterDefinition).where(
                ToolAdapterDefinition.code == profile.adapter_code,
                ToolAdapterDefinition.enabled.is_(True),
            )
        )
        if not definition:
            raise ValueError("Adapter is unknown or disabled")
        if profile.adapter_code == "cyberaudit.external_result_import":
            raise ValueError("Use the imports preview and confirmation workflow")
        if payload.asset_id:
            asset = await db.scalar(
                select(Asset).where(
                    Asset.id == payload.asset_id,
                    Asset.organization_id == user.organization_id,
                    Asset.engagement_id == engagement.id,
                    Asset.deleted_at.is_(None),
                )
            )
            if not asset:
                raise ValueError("Asset not found in this engagement")
        if payload.target_type.value not in profile.target_types:
            raise ValueError("Target type not supported by profile")
        if INTENSITY_ORDER[payload.intensity] > INTENSITY_ORDER[profile.maximum_intensity]:
            raise ValueError("Requested intensity exceeds profile maximum")
        adapter = self.registry.get(profile.adapter_code)
        metadata = adapter.metadata()
        if payload.intensity not in metadata.supported_intensities:
            raise ValueError("Intensity not supported by adapter")
        configuration = {**profile.default_configuration, **payload.configuration}
        config_result = await adapter.validate_configuration(configuration)
        if not config_result.valid:
            raise ValueError("; ".join(config_result.errors))
        normalized = normalized_target(payload.target_type, payload.target_value)
        target = NormalizedTarget(target_type=payload.target_type, value=normalized)
        target_result = await adapter.validate_target(target)
        if not target_result.valid:
            raise ValueError("; ".join(target_result.errors))
        job = ScanJob(
            organization_id=user.organization_id,
            engagement_id=engagement.id,
            scope_id=scope.id,
            asset_id=payload.asset_id,
            scan_profile_id=profile.id,
            adapter_code=profile.adapter_code,
            target_type=payload.target_type,
            target_value=payload.target_value,
            normalized_target=normalized,
            technique=payload.technique,
            intensity=payload.intensity,
            configuration=configuration,
            status=JobStatus.DRAFT,
            priority=payload.priority,
            requested_by=user.id,
            progress=0,
            status_message="Pedido criado",
        )
        db.add(job)
        await db.flush()
        db.add(
            JobEvent(
                organization_id=user.organization_id,
                job_id=job.id,
                event_type=EventType.CREATED,
                severity="info",
                message="Job criado pelo orquestrador",
                event_metadata={"adapter_code": job.adapter_code},
            )
        )
        await transition_job(db, job, JobStatus.PENDING_POLICY, "A validar política", actor=user)
        policy = await self.policy_engine.evaluate(
            db,
            PolicyRequest(
                organization_id=user.organization_id,
                engagement_id=engagement.id,
                operator_id=user.id,
                target_type=payload.target_type,
                target_value=normalized,
                technique=payload.technique,
                requested_intensity=payload.intensity,
                requested_at=datetime.now(timezone.utc),
            ),
        )
        await update_progress(db, job, 5, "Política avaliada")
        db.add(
            JobEvent(
                organization_id=user.organization_id,
                job_id=job.id,
                event_type=EventType.POLICY_EVALUATED,
                severity="warning" if policy.decision != "allowed" else "info",
                message=f"Decisão de política: {policy.decision}",
                event_metadata=policy.model_dump(mode="json"),
            )
        )
        if policy.decision == "denied":
            job.error_code = "POLICY_DENIED"
            job.error_message = "; ".join(policy.reasons)
            await transition_job(
                db,
                job,
                JobStatus.DENIED,
                "Job bloqueado pelo ScopePolicyEngine",
                {"reasons": policy.reasons},
                user,
            )
        else:
            requires_approval = (
                policy.decision == "requires_approval"
                or profile.requires_approval
                or payload.intensity in {Intensity.ELEVATED, Intensity.INTRUSIVE}
            )
            if requires_approval:
                approval = Approval(
                    organization_id=user.organization_id,
                    engagement_id=engagement.id,
                    job_id=job.id,
                    requested_by=user.id,
                    approval_type="scan_job",
                    reason=payload.approval_reason or "Avaliação de risco elevado",
                    risk_summary={
                        "target": normalized,
                        "technique": payload.technique,
                        "intensity": payload.intensity.value,
                        "duration_seconds": profile.timeout_seconds,
                        "scope_id": scope.id,
                        "configuration": configuration,
                    },
                    status=ApprovalStatus.PENDING,
                    expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
                )
                db.add(approval)
                await db.flush()
                job.approval_id = approval.id
                await transition_job(
                    db,
                    job,
                    JobStatus.PENDING_APPROVAL,
                    "A aguardar aprovação",
                    actor=user,
                )
            else:
                await self._queue(db, job, user)
        await write_audit(db, user, "job.created", "scan_job", job.id)
        jobs_created.labels(adapter_code=job.adapter_code).inc()
        if job.status == JobStatus.DENIED:
            policy_denials.inc()
        structured_event(
            "job_created",
            organization_id=job.organization_id,
            engagement_id=job.engagement_id,
            job_id=job.id,
            adapter_code=job.adapter_code,
            result=job.status.value,
        )
        await db.commit()
        await db.refresh(job)
        return job

    async def _queue(self, db: AsyncSession, job: ScanJob, actor: User) -> None:
        await transition_job(db, job, JobStatus.QUEUED, "Enfileirado", actor=actor)
        await update_progress(db, job, 10, "Job enviado para a fila")
        await db.flush()
        self.enqueue(job.id)

    async def approve(
        self,
        db: AsyncSession,
        approval: Approval,
        reviewer: User,
        notes: str | None,
    ) -> ScanJob:
        if approval.organization_id != reviewer.organization_id:
            raise ValueError("Approval not found")
        if approval.status != ApprovalStatus.PENDING:
            raise ValueError("Approval is not pending")
        if approval_is_expired(approval.expires_at):
            approval.status = ApprovalStatus.EXPIRED
            raise ValueError("Approval expired")
        job = await db.get(ScanJob, approval.job_id)
        if not job or job.organization_id != reviewer.organization_id:
            raise ValueError("Job not found")
        approval.status = ApprovalStatus.APPROVED
        approval.reviewed_by = reviewer.id
        approval.reviewed_at = utcnow()
        approval.review_notes = notes
        job.approved_by = reviewer.id
        await transition_job(db, job, JobStatus.APPROVED, "Aprovação concedida", actor=reviewer)
        await self._queue(db, job, reviewer)
        await write_audit(db, reviewer, "approval.approved", "approval", approval.id)
        approvals.labels(decision="approved").inc()
        await db.commit()
        await db.refresh(job)
        return job

    async def reject(
        self,
        db: AsyncSession,
        approval: Approval,
        reviewer: User,
        notes: str | None,
    ) -> ScanJob:
        if approval.organization_id != reviewer.organization_id:
            raise ValueError("Approval not found")
        if approval.status != ApprovalStatus.PENDING:
            raise ValueError("Approval is not pending")
        job = await db.get(ScanJob, approval.job_id)
        if not job or job.organization_id != reviewer.organization_id:
            raise ValueError("Job not found")
        approval.status = ApprovalStatus.REJECTED
        approval.reviewed_by = reviewer.id
        approval.reviewed_at = utcnow()
        approval.review_notes = notes
        await transition_job(db, job, JobStatus.DENIED, "Aprovação rejeitada", actor=reviewer)
        await write_audit(db, reviewer, "approval.rejected", "approval", approval.id)
        approvals.labels(decision="rejected").inc()
        await db.commit()
        return job

    async def cancel(self, db: AsyncSession, job: ScanJob, actor: User) -> ScanJob:
        if job.organization_id != actor.organization_id:
            raise ValueError("Job not found")
        if job.status == JobStatus.PENDING_APPROVAL:
            await transition_job(
                db, job, JobStatus.CANCELLED, "Cancelado antes da aprovação", actor=actor
            )
        elif job.status in {JobStatus.QUEUED, JobStatus.STARTING, JobStatus.RUNNING}:
            await transition_job(
                db, job, JobStatus.CANCELLING, "Cancelamento solicitado", actor=actor
            )
        else:
            raise InvalidJobTransition(f"Cannot cancel job in {job.status.value}")
        await db.commit()
        await db.refresh(job)
        return job

    async def retry(self, db: AsyncSession, job: ScanJob, actor: User) -> ScanJob:
        if job.organization_id != actor.organization_id:
            raise ValueError("Job not found")
        if job.status not in {
            JobStatus.FAILED,
            JobStatus.TIMED_OUT,
            JobStatus.CANCELLED,
            JobStatus.COMPLETED_WITH_WARNINGS,
        }:
            raise InvalidJobTransition("Only terminal unsuccessful jobs can be retried")
        payload = JobCreate(
            engagement_id=job.engagement_id,
            scope_id=job.scope_id,
            asset_id=job.asset_id,
            scan_profile_id=job.scan_profile_id,
            target_type=job.target_type,
            target_value=job.target_value,
            technique=job.technique,
            intensity=job.intensity,
            configuration=job.configuration,
            priority=job.priority,
        )
        retried = await self.create_job(db, actor, payload)
        retried.retry_count = job.retry_count + 1
        await db.commit()
        return retried
