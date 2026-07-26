import asyncio
import json

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from cyberaudit.adapters import AdapterRegistry
from cyberaudit.audit import write_audit
from cyberaudit.db import SessionLocal, get_db
from cyberaudit.execution_schemas import (
    ApprovalReview,
    FindingRead,
    JobCreate,
    JobEventRead,
    JobRead,
    ScanProfileCreate,
    ScanProfilePatch,
    ScanProfileRead,
)
from cyberaudit.models import (
    Approval,
    Finding,
    JobEvent,
    JobStatus,
    RawResult,
    ScanJob,
    ScanProfile,
    ToolAdapterDefinition,
    User,
)
from cyberaudit.orchestrator import InvalidJobTransition, JobOrchestrator
from cyberaudit.policy import ScopePolicyEngine
from cyberaudit.queue import enqueue_job
from cyberaudit.security import require_permission

router = APIRouter(prefix="/api/v1")
registry = AdapterRegistry()
orchestrator = JobOrchestrator(ScopePolicyEngine(), registry, enqueue_job)


async def page(db, model, where, page_number: int, page_size: int, order):
    total = await db.scalar(select(func.count()).select_from(model).where(*where))
    items = list(
        (
            await db.scalars(
                select(model)
                .where(*where)
                .order_by(order)
                .offset((page_number - 1) * page_size)
                .limit(page_size)
            )
        ).all()
    )
    return {
        "items": items,
        "total": total or 0,
        "page": page_number,
        "page_size": page_size,
    }


@router.get("/scan-profiles", tags=["execution"])
async def list_profiles(
    q: str = "",
    page_number: int = Query(1, ge=1, alias="page"),
    page_size: int = Query(20, ge=1, le=100),
    user: User = Depends(require_permission("scan_profiles.read")),
    db: AsyncSession = Depends(get_db),
):
    where = [
        ScanProfile.organization_id == user.organization_id,
        ScanProfile.deleted_at.is_(None),
    ]
    if q:
        where.append(ScanProfile.name.ilike(f"%{q}%"))
    return await page(db, ScanProfile, where, page_number, page_size, ScanProfile.name)


@router.post("/scan-profiles", response_model=ScanProfileRead, status_code=201, tags=["execution"])
async def create_profile(
    payload: ScanProfileCreate,
    user: User = Depends(require_permission("scan_profiles.manage")),
    db: AsyncSession = Depends(get_db),
):
    try:
        adapter = registry.get(payload.adapter_code)
    except LookupError as exc:
        raise HTTPException(422, str(exc)) from exc
    validation = await adapter.validate_configuration(payload.default_configuration)
    if not validation.valid:
        raise HTTPException(422, "; ".join(validation.errors))
    metadata = adapter.metadata()
    if payload.network_access and not metadata.requires_network:
        raise HTTPException(422, "Profile cannot enable network for a networkless adapter")
    profile = ScanProfile(
        organization_id=user.organization_id,
        configuration_schema=metadata.configuration_schema,
        created_by=user.id,
        **payload.model_dump(mode="json"),
    )
    db.add(profile)
    await db.flush()
    await write_audit(db, user, "scan_profile.created", "scan_profile", profile.id)
    await db.commit()
    await db.refresh(profile)
    return profile


async def tenant_profile(db: AsyncSession, profile_id: str, organization_id: str):
    profile = await db.scalar(
        select(ScanProfile).where(
            ScanProfile.id == profile_id,
            ScanProfile.organization_id == organization_id,
            ScanProfile.deleted_at.is_(None),
        )
    )
    if not profile:
        raise HTTPException(404, "Scan profile not found")
    return profile


@router.get("/scan-profiles/{profile_id}", response_model=ScanProfileRead, tags=["execution"])
async def get_profile(
    profile_id: str,
    user: User = Depends(require_permission("scan_profiles.read")),
    db: AsyncSession = Depends(get_db),
):
    return await tenant_profile(db, profile_id, user.organization_id)


@router.patch("/scan-profiles/{profile_id}", response_model=ScanProfileRead, tags=["execution"])
async def patch_profile(
    profile_id: str,
    payload: ScanProfilePatch,
    user: User = Depends(require_permission("scan_profiles.manage")),
    db: AsyncSession = Depends(get_db),
):
    profile = await tenant_profile(db, profile_id, user.organization_id)
    values = payload.model_dump(exclude_unset=True)
    if "default_configuration" in values:
        validation = await registry.get(profile.adapter_code).validate_configuration(
            values["default_configuration"]
        )
        if not validation.valid:
            raise HTTPException(422, "; ".join(validation.errors))
    for key, value in values.items():
        setattr(profile, key, value)
    await write_audit(db, user, "scan_profile.updated", "scan_profile", profile.id)
    await db.commit()
    await db.refresh(profile)
    return profile


@router.get("/adapters", tags=["execution"])
async def list_adapters(
    user: User = Depends(require_permission("adapters.read")),
    db: AsyncSession = Depends(get_db),
):
    definitions = {
        item.code: item
        for item in (
            await db.scalars(select(ToolAdapterDefinition).order_by(ToolAdapterDefinition.code))
        ).all()
    }
    result = []
    for metadata in registry.metadata():
        definition = definitions.get(metadata.code)
        result.append(
            {
                **metadata.model_dump(mode="json"),
                "enabled": definition.enabled if definition else True,
                "health_status": definition.health_status if definition else "unknown",
            }
        )
    return result


@router.get("/adapters/{code}", tags=["execution"])
async def get_adapter(
    code: str,
    user: User = Depends(require_permission("adapters.read")),
):
    try:
        return registry.get(code).metadata()
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc


@router.post("/adapters/{code}/health-check", tags=["execution"])
async def adapter_health(
    code: str,
    user: User = Depends(require_permission("adapters.manage")),
    db: AsyncSession = Depends(get_db),
):
    try:
        result = await registry.health_check(code)
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc
    definition = await db.scalar(
        select(ToolAdapterDefinition).where(ToolAdapterDefinition.code == code)
    )
    if definition:
        definition.health_status = "online" if result.healthy else "offline"
        definition.last_health_check_at = result.checked_at
        await db.commit()
    return result


@router.get("/jobs", tags=["execution"])
async def list_jobs(
    q: str = "",
    status: JobStatus | None = None,
    page_number: int = Query(1, ge=1, alias="page"),
    page_size: int = Query(20, ge=1, le=100),
    user: User = Depends(require_permission("jobs.read")),
    db: AsyncSession = Depends(get_db),
):
    where = [ScanJob.organization_id == user.organization_id]
    if status:
        where.append(ScanJob.status == status)
    if q:
        where.append(
            or_(
                ScanJob.target_value.ilike(f"%{q}%"),
                ScanJob.adapter_code.ilike(f"%{q}%"),
            )
        )
    return await page(db, ScanJob, where, page_number, page_size, ScanJob.created_at.desc())


@router.post("/jobs", response_model=JobRead, status_code=201, tags=["execution"])
async def create_job(
    payload: JobCreate,
    user: User = Depends(require_permission("jobs.create")),
    db: AsyncSession = Depends(get_db),
):
    try:
        return await orchestrator.create_job(db, user, payload)
    except (ValueError, LookupError) as exc:
        raise HTTPException(422, str(exc)) from exc


async def tenant_job(db: AsyncSession, job_id: str, organization_id: str):
    job = await db.scalar(
        select(ScanJob).where(
            ScanJob.id == job_id,
            ScanJob.organization_id == organization_id,
        )
    )
    if not job:
        raise HTTPException(404, "Job not found")
    return job


@router.get("/jobs/{job_id}", response_model=JobRead, tags=["execution"])
async def get_job(
    job_id: str,
    user: User = Depends(require_permission("jobs.read")),
    db: AsyncSession = Depends(get_db),
):
    return await tenant_job(db, job_id, user.organization_id)


@router.post("/jobs/{job_id}/cancel", response_model=JobRead, tags=["execution"])
async def cancel_job(
    job_id: str,
    user: User = Depends(require_permission("jobs.cancel")),
    db: AsyncSession = Depends(get_db),
):
    job = await tenant_job(db, job_id, user.organization_id)
    try:
        return await orchestrator.cancel(db, job, user)
    except InvalidJobTransition as exc:
        raise HTTPException(409, str(exc)) from exc


@router.post("/jobs/{job_id}/retry", response_model=JobRead, status_code=201, tags=["execution"])
async def retry_job(
    job_id: str,
    user: User = Depends(require_permission("jobs.retry")),
    db: AsyncSession = Depends(get_db),
):
    job = await tenant_job(db, job_id, user.organization_id)
    try:
        return await orchestrator.retry(db, job, user)
    except InvalidJobTransition as exc:
        raise HTTPException(409, str(exc)) from exc


@router.get("/jobs/{job_id}/events", tags=["execution"])
async def job_events(
    job_id: str,
    user: User = Depends(require_permission("jobs.read")),
    db: AsyncSession = Depends(get_db),
):
    await tenant_job(db, job_id, user.organization_id)
    items = list(
        (
            await db.scalars(
                select(JobEvent)
                .where(
                    JobEvent.job_id == job_id,
                    JobEvent.organization_id == user.organization_id,
                )
                .order_by(JobEvent.created_at)
            )
        ).all()
    )
    return [JobEventRead.model_validate(item) for item in items]


@router.get("/jobs/{job_id}/results", tags=["execution"])
async def job_results(
    job_id: str,
    user: User = Depends(require_permission("jobs.read")),
    db: AsyncSession = Depends(get_db),
):
    job = await tenant_job(db, job_id, user.organization_id)
    findings = list(
        (
            await db.scalars(
                select(Finding).where(
                    Finding.job_id == job.id,
                    Finding.organization_id == user.organization_id,
                )
            )
        ).all()
    )
    raw = await db.scalar(
        select(RawResult).where(
            RawResult.job_id == job.id,
            RawResult.organization_id == user.organization_id,
        )
    )
    return {
        "summary": job.result_summary,
        "findings": [FindingRead.model_validate(item) for item in findings],
        "raw_result": (
            {
                "id": raw.id,
                "format": raw.format,
                "content_hash": raw.content_hash,
                "size_bytes": raw.size_bytes,
                "sanitized": raw.sanitized,
                "untrusted": True,
            }
            if raw
            else None
        ),
    }


@router.get("/jobs/{job_id}/stream", tags=["execution"])
async def stream_job(
    job_id: str,
    user: User = Depends(require_permission("jobs.read")),
    db: AsyncSession = Depends(get_db),
):
    await tenant_job(db, job_id, user.organization_id)
    organization_id = user.organization_id

    async def events():
        last_state: tuple[str, int, str] | None = None
        for _ in range(600):
            async with SessionLocal() as stream_db:
                job = await stream_db.scalar(
                    select(ScanJob).where(
                        ScanJob.id == job_id,
                        ScanJob.organization_id == organization_id,
                    )
                )
                if not job:
                    return
                state = (job.status.value, job.progress, job.status_message)
                if state != last_state:
                    yield f"event: job\ndata: {json.dumps({'status': state[0], 'progress': state[1], 'message': state[2]})}\n\n"
                    last_state = state
                if job.status in {
                    JobStatus.DENIED,
                    JobStatus.COMPLETED,
                    JobStatus.COMPLETED_WITH_WARNINGS,
                    JobStatus.FAILED,
                    JobStatus.TIMED_OUT,
                    JobStatus.CANCELLED,
                }:
                    return
            await asyncio.sleep(1)

    return StreamingResponse(events(), media_type="text/event-stream")


@router.get("/approvals", tags=["execution"])
async def list_approvals(
    page_number: int = Query(1, ge=1, alias="page"),
    page_size: int = Query(20, ge=1, le=100),
    user: User = Depends(require_permission("approvals.read")),
    db: AsyncSession = Depends(get_db),
):
    return await page(
        db,
        Approval,
        [Approval.organization_id == user.organization_id],
        page_number,
        page_size,
        Approval.created_at.desc(),
    )


async def tenant_approval(db: AsyncSession, approval_id: str, organization_id: str):
    approval = await db.scalar(
        select(Approval).where(
            Approval.id == approval_id,
            Approval.organization_id == organization_id,
        )
    )
    if not approval:
        raise HTTPException(404, "Approval not found")
    return approval


@router.post("/approvals/{approval_id}/approve", response_model=JobRead, tags=["execution"])
async def approve(
    approval_id: str,
    payload: ApprovalReview,
    user: User = Depends(require_permission("approvals.review")),
    db: AsyncSession = Depends(get_db),
):
    approval = await tenant_approval(db, approval_id, user.organization_id)
    try:
        return await orchestrator.approve(db, approval, user, payload.notes)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc


@router.post("/approvals/{approval_id}/reject", response_model=JobRead, tags=["execution"])
async def reject(
    approval_id: str,
    payload: ApprovalReview,
    user: User = Depends(require_permission("approvals.review")),
    db: AsyncSession = Depends(get_db),
):
    approval = await tenant_approval(db, approval_id, user.organization_id)
    try:
        return await orchestrator.reject(db, approval, user, payload.notes)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc


@router.get("/findings", tags=["execution"])
async def list_findings(
    q: str = "",
    page_number: int = Query(1, ge=1, alias="page"),
    page_size: int = Query(20, ge=1, le=100),
    user: User = Depends(require_permission("findings.read")),
    db: AsyncSession = Depends(get_db),
):
    where = [Finding.organization_id == user.organization_id]
    if q:
        where.append(or_(Finding.title.ilike(f"%{q}%"), Finding.category.ilike(f"%{q}%")))
    return await page(db, Finding, where, page_number, page_size, Finding.last_seen_at.desc())


@router.get("/findings/{finding_id}", response_model=FindingRead, tags=["execution"])
async def get_finding(
    finding_id: str,
    user: User = Depends(require_permission("findings.read")),
    db: AsyncSession = Depends(get_db),
):
    finding = await db.scalar(
        select(Finding).where(
            Finding.id == finding_id,
            Finding.organization_id == user.organization_id,
        )
    )
    if not finding:
        raise HTTPException(404, "Finding not found")
    return finding
