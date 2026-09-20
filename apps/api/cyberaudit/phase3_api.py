from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile
from fastapi.responses import Response
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from cyberaudit.adapters import NormalizedFinding, finding_fingerprint
from cyberaudit.audit import write_audit
from cyberaudit.correlation import FindingCorrelationService
from cyberaudit.db import get_db
from cyberaudit.execution_api import orchestrator
from cyberaudit.execution_schemas import JobCreate
from cyberaudit.imports import (
    ALLOWED_IMPORT_EXTENSIONS,
    ALLOWED_IMPORT_MIME_TYPES,
    MAX_IMPORT_BYTES,
    ImportPreview,
    detect_import_format,
    parse_import,
)
from cyberaudit.models import (
    AssetObservation,
    AssetSuggestion,
    Evidence,
    EvidenceSensitivity,
    ExternalImport,
    ExternalImportStatus,
    Finding,
    FindingEvidence,
    Intensity,
    JobPriority,
    JobStatus,
    Retest,
    RetestStatus,
    ScanJob,
    ScanProfile,
    Scope,
    ScopeTarget,
    SuggestionStatus,
    User,
    utcnow,
)
from cyberaudit.network_security import build_network_policy
from cyberaudit.observability import asset_suggestions, imports_total, retests_total
from cyberaudit.policy import ScopePolicyEngine
from cyberaudit.schemas import PolicyRequest
from cyberaudit.security import require_permission
from cyberaudit.storage import LocalStorage

router = APIRouter(prefix="/api/v1", tags=["safe-assessments"])
storage = LocalStorage()
correlation = FindingCorrelationService()
policy_engine = ScopePolicyEngine()


async def _page(
    db: AsyncSession,
    model,
    where: list,
    page_number: int,
    page_size: int,
    order,
):
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
    return {"items": items, "total": total or 0, "page": page_number, "page_size": page_size}


@router.get("/evidence")
async def list_evidence(
    job_id: str | None = None,
    finding_id: str | None = None,
    engagement_id: str | None = None,
    page_number: int = Query(1, ge=1, alias="page"),
    page_size: int = Query(20, ge=1, le=100),
    user: User = Depends(require_permission("evidence.read")),
    db: AsyncSession = Depends(get_db),
):
    where = [Evidence.organization_id == user.organization_id]
    if job_id:
        where.append(Evidence.job_id == job_id)
    if engagement_id:
        where.append(Evidence.engagement_id == engagement_id)
    if finding_id:
        linked_ids = select(FindingEvidence.evidence_id).where(
            FindingEvidence.finding_id == finding_id
        )
        where.append((Evidence.finding_id == finding_id) | Evidence.id.in_(linked_ids))
    return await _page(db, Evidence, where, page_number, page_size, Evidence.created_at.desc())


async def _tenant_evidence(db: AsyncSession, evidence_id: str, organization_id: str) -> Evidence:
    evidence = await db.scalar(
        select(Evidence).where(
            Evidence.id == evidence_id,
            Evidence.organization_id == organization_id,
        )
    )
    if not evidence:
        raise HTTPException(404, "Evidence not found")
    return evidence


@router.get("/evidence/{evidence_id}")
async def get_evidence(
    evidence_id: str,
    user: User = Depends(require_permission("evidence.read")),
    db: AsyncSession = Depends(get_db),
):
    return await _tenant_evidence(db, evidence_id, user.organization_id)


@router.get("/evidence/{evidence_id}/download")
async def download_evidence(
    evidence_id: str,
    user: User = Depends(require_permission("evidence.download")),
    db: AsyncSession = Depends(get_db),
):
    evidence = await _tenant_evidence(db, evidence_id, user.organization_id)
    if evidence.storage_key:
        content = storage.read_private_file(evidence.storage_key, MAX_IMPORT_BYTES)
    else:
        content = (evidence.sanitized_content or "").encode()
    await write_audit(db, user, "evidence.downloaded", "evidence", evidence.id)
    await db.commit()
    return Response(
        content,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="evidence-{evidence.id}.txt"',
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'none'; sandbox",
            "Cache-Control": "private, no-store",
        },
    )


@router.post("/imports", status_code=201)
async def create_import(
    engagement_id: str = Form(...),
    upload: UploadFile = File(...),
    user: User = Depends(require_permission("imports.create")),
    db: AsyncSession = Depends(get_db),
):
    scope = await db.scalar(
        select(Scope).where(
            Scope.organization_id == user.organization_id,
            Scope.engagement_id == engagement_id,
            Scope.status == "active",
            Scope.deleted_at.is_(None),
        )
    )
    if not scope:
        raise HTTPException(422, "Authorized active scope required")
    filename = Path(upload.filename or "").name
    if filename != upload.filename:
        raise HTTPException(422, "Unsafe filename")
    try:
        format_name = detect_import_format(filename, upload.content_type or "")
        key, digest, size = await storage.save_private_file(
            upload,
            allowed_extensions=ALLOWED_IMPORT_EXTENSIONS,
            allowed_mime_types=ALLOWED_IMPORT_MIME_TYPES,
            maximum_bytes=MAX_IMPORT_BYTES,
        )
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    item = ExternalImport(
        organization_id=user.organization_id,
        engagement_id=engagement_id,
        uploaded_by=user.id,
        filename=filename,
        storage_key=key,
        content_hash=digest,
        mime_type=upload.content_type or "application/octet-stream",
        format=format_name,
        size_bytes=size,
    )
    db.add(item)
    await db.flush()
    await write_audit(db, user, "import.uploaded", "external_import", item.id)
    await db.commit()
    await db.refresh(item)
    imports_total.labels(result="uploaded").inc()
    return item


async def _tenant_import(db: AsyncSession, import_id: str, organization_id: str) -> ExternalImport:
    item = await db.scalar(
        select(ExternalImport).where(
            ExternalImport.id == import_id,
            ExternalImport.organization_id == organization_id,
        )
    )
    if not item:
        raise HTTPException(404, "Import not found")
    return item


@router.get("/imports")
async def list_imports(
    page_number: int = Query(1, ge=1, alias="page"),
    page_size: int = Query(20, ge=1, le=100),
    user: User = Depends(require_permission("imports.read")),
    db: AsyncSession = Depends(get_db),
):
    return await _page(
        db,
        ExternalImport,
        [ExternalImport.organization_id == user.organization_id],
        page_number,
        page_size,
        ExternalImport.created_at.desc(),
    )


@router.get("/imports/{import_id}")
async def get_import(
    import_id: str,
    user: User = Depends(require_permission("imports.read")),
    db: AsyncSession = Depends(get_db),
):
    return await _tenant_import(db, import_id, user.organization_id)


@router.post("/imports/{import_id}/preview")
async def preview_import(
    import_id: str,
    user: User = Depends(require_permission("imports.read")),
    db: AsyncSession = Depends(get_db),
):
    item = await _tenant_import(db, import_id, user.organization_id)
    if item.status in {ExternalImportStatus.CONFIRMED, ExternalImportStatus.CANCELLED}:
        raise HTTPException(409, "Import cannot be previewed in its current state")
    try:
        preview = parse_import(
            storage.read_private_file(item.storage_key, MAX_IMPORT_BYTES), item.format
        )
    except ValueError as exc:
        item.status = ExternalImportStatus.FAILED
        item.error_message = str(exc)
        await db.commit()
        raise HTTPException(422, str(exc)) from exc
    item.preview = preview.model_dump(mode="json")
    item.status = ExternalImportStatus.PREVIEWED
    await write_audit(db, user, "import.previewed", "external_import", item.id)
    await db.commit()
    return preview


@router.post("/imports/{import_id}/confirm")
async def confirm_import(
    import_id: str,
    user: User = Depends(require_permission("imports.confirm")),
    db: AsyncSession = Depends(get_db),
):
    item = await _tenant_import(db, import_id, user.organization_id)
    if item.status != ExternalImportStatus.PREVIEWED:
        raise HTTPException(409, "Preview is required before confirmation")
    preview = ImportPreview.model_validate(item.preview)
    scope = await db.scalar(
        select(Scope).where(
            Scope.organization_id == user.organization_id,
            Scope.engagement_id == item.engagement_id,
            Scope.status == "active",
            Scope.deleted_at.is_(None),
        )
    )
    profile = await db.scalar(
        select(ScanProfile).where(
            ScanProfile.organization_id == user.organization_id,
            ScanProfile.adapter_code == "cyberaudit.external_result_import",
            ScanProfile.enabled.is_(True),
        )
    )
    if not scope or not profile:
        raise HTTPException(422, "Import profile and active scope are required")
    target = await db.scalar(
        select(ScopeTarget).where(ScopeTarget.scope_id == scope.id, ScopeTarget.allowed.is_(True))
    )
    if not target:
        raise HTTPException(422, "Authorized target is required")
    policy = await policy_engine.evaluate(
        db,
        PolicyRequest(
            organization_id=user.organization_id,
            engagement_id=item.engagement_id,
            operator_id=user.id,
            target_type=target.target_type,
            target_value=target.normalized_value,
            technique="external-result-import",
            requested_intensity=Intensity.PASSIVE,
            requested_at=datetime.now(timezone.utc),
        ),
    )
    if policy.decision != "allowed":
        raise HTTPException(422, f"Import blocked by policy: {'; '.join(policy.reasons)}")
    job = ScanJob(
        organization_id=user.organization_id,
        engagement_id=item.engagement_id,
        scope_id=scope.id,
        scan_profile_id=profile.id,
        adapter_code=profile.adapter_code,
        target_type=target.target_type,
        target_value=target.target_value,
        normalized_target=target.normalized_value,
        technique="external-result-import",
        intensity=Intensity.PASSIVE,
        configuration={"import_id": item.id},
        status=JobStatus.COMPLETED,
        priority=JobPriority.NORMAL,
        requested_by=user.id,
        queued_at=utcnow(),
        started_at=utcnow(),
        completed_at=utcnow(),
        progress=100,
        status_message="Importação confirmada",
        result_summary={"imported": True, "finding_count": preview.finding_count},
    )
    db.add(job)
    await db.flush()
    evidence = Evidence(
        organization_id=user.organization_id,
        engagement_id=item.engagement_id,
        job_id=job.id,
        evidence_type="imported_file",
        title=f"Importação {item.filename}",
        description="Ficheiro privado, não executável e não renderizado no browser.",
        storage_key=item.storage_key,
        content_hash=item.content_hash,
        mime_type=item.mime_type,
        size_bytes=item.size_bytes,
        sensitivity=EvidenceSensitivity.CONFIDENTIAL,
        redacted=False,
        collected_by_adapter=profile.adapter_code,
        evidence_metadata={"import_id": item.id, "untrusted": True, "imported": True},
    )
    db.add(evidence)
    await db.flush()
    created = 0
    deduplicated = 0
    for imported in preview.findings:
        normalized = NormalizedFinding(
            title=imported.title,
            description=imported.description,
            category=imported.category,
            severity=imported.severity,
            confidence=imported.confidence,
            affected_component=imported.affected_component,
            technical_impact=imported.description or "Impacto por validar.",
            business_impact="Impacto importado; requer revisão humana.",
            remediation=imported.remediation,
            validation_steps=["Validar o resultado com uma avaliação autorizada."],
            evidence=[],
            references=imported.references,
            source_identifier=imported.source_identifier,
            logical_location=imported.affected_component,
            simulated=False,
            imported=True,
            observed_value=imported.observed_value,
            expected_value=imported.expected_value,
            verification_status="unverified",
        )
        fingerprint = finding_fingerprint(
            user.organization_id, item.engagement_id, None, normalized, profile.adapter_code
        )
        existing = await db.scalar(
            select(Finding).where(
                Finding.organization_id == user.organization_id,
                Finding.fingerprint == fingerprint,
            )
        )
        if existing:
            existing.last_seen_at = utcnow()
            existing.job_id = job.id
            finding = existing
            deduplicated += 1
        else:
            finding = Finding(
                organization_id=user.organization_id,
                engagement_id=item.engagement_id,
                job_id=job.id,
                title=normalized.title,
                description=normalized.description,
                category=normalized.category,
                technical_severity=normalized.severity,
                confidence=normalized.confidence,
                affected_component=normalized.affected_component,
                technical_impact=normalized.technical_impact,
                business_impact=normalized.business_impact,
                remediation_summary=normalized.remediation,
                validation_steps=normalized.validation_steps,
                source_adapter=profile.adapter_code,
                fingerprint=fingerprint,
                references=normalized.references,
                observed_value=normalized.observed_value,
                expected_value=normalized.expected_value,
                location=normalized.logical_location,
                imported=True,
                simulated=False,
            )
            db.add(finding)
            await db.flush()
            created += 1
        db.add(FindingEvidence(finding_id=finding.id, evidence_id=evidence.id, job_id=job.id))
    correlation_result = await correlation.correlate_engagement(
        db, organization_id=user.organization_id, engagement_id=item.engagement_id
    )
    item.status = ExternalImportStatus.CONFIRMED
    item.confirmed_job_id = job.id
    job.result_summary = {
        "imported": True,
        "findings_created": created,
        "findings_deduplicated": deduplicated,
        "correlation": correlation_result,
    }
    await write_audit(db, user, "import.confirmed", "external_import", item.id)
    await db.commit()
    imports_total.labels(result="confirmed").inc()
    return {"import_id": item.id, "job_id": job.id, **job.result_summary}


@router.post("/imports/{import_id}/cancel")
async def cancel_import(
    import_id: str,
    user: User = Depends(require_permission("imports.create")),
    db: AsyncSession = Depends(get_db),
):
    item = await _tenant_import(db, import_id, user.organization_id)
    if item.status == ExternalImportStatus.CONFIRMED:
        raise HTTPException(409, "Confirmed import cannot be cancelled")
    item.status = ExternalImportStatus.CANCELLED
    await write_audit(db, user, "import.cancelled", "external_import", item.id)
    await db.commit()
    imports_total.labels(result="cancelled").inc()
    return item


@router.get("/retests")
async def list_retests(
    page_number: int = Query(1, ge=1, alias="page"),
    page_size: int = Query(20, ge=1, le=100),
    user: User = Depends(require_permission("retests.read")),
    db: AsyncSession = Depends(get_db),
):
    return await _page(
        db,
        Retest,
        [Retest.organization_id == user.organization_id],
        page_number,
        page_size,
        Retest.created_at.desc(),
    )


@router.post("/findings/{finding_id}/retest", status_code=201)
async def create_retest(
    finding_id: str,
    user: User = Depends(require_permission("retests.create")),
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
    original = await db.get(ScanJob, finding.job_id)
    if not original:
        raise HTTPException(409, "Original job not found")
    payload = JobCreate(
        engagement_id=original.engagement_id,
        scope_id=original.scope_id,
        asset_id=original.asset_id,
        scan_profile_id=original.scan_profile_id,
        target_type=original.target_type,
        target_value=original.normalized_target,
        technique=original.technique,
        intensity=original.intensity,
        configuration=original.configuration,
        priority=JobPriority.NORMAL,
    )
    try:
        retest_job = await orchestrator.create_job(db, user, payload)
    except (ValueError, LookupError) as exc:
        raise HTTPException(422, str(exc)) from exc
    retest = Retest(
        organization_id=user.organization_id,
        engagement_id=finding.engagement_id,
        finding_id=finding.id,
        original_job_id=original.id,
        retest_job_id=retest_job.id,
        requested_by=user.id,
        status=(
            RetestStatus.QUEUED if retest_job.status == JobStatus.QUEUED else RetestStatus.REQUESTED
        ),
    )
    db.add(retest)
    await db.flush()
    await write_audit(db, user, "retest.requested", "retest", retest.id)
    await db.commit()
    retests_total.labels(result="requested").inc()
    return retest


@router.get("/retests/{retest_id}")
async def get_retest(
    retest_id: str,
    user: User = Depends(require_permission("retests.read")),
    db: AsyncSession = Depends(get_db),
):
    item = await db.scalar(
        select(Retest).where(
            Retest.id == retest_id,
            Retest.organization_id == user.organization_id,
        )
    )
    if not item:
        raise HTTPException(404, "Retest not found")
    return item


@router.get("/asset-observations")
async def list_asset_observations(
    page_number: int = Query(1, ge=1, alias="page"),
    page_size: int = Query(20, ge=1, le=100),
    user: User = Depends(require_permission("asset_observations.read")),
    db: AsyncSession = Depends(get_db),
):
    return await _page(
        db,
        AssetObservation,
        [AssetObservation.organization_id == user.organization_id],
        page_number,
        page_size,
        AssetObservation.observed_at.desc(),
    )


@router.get("/asset-suggestions")
async def list_asset_suggestions(
    page_number: int = Query(1, ge=1, alias="page"),
    page_size: int = Query(20, ge=1, le=100),
    user: User = Depends(require_permission("asset_observations.read")),
    db: AsyncSession = Depends(get_db),
):
    return await _page(
        db,
        AssetSuggestion,
        [AssetSuggestion.organization_id == user.organization_id],
        page_number,
        page_size,
        AssetSuggestion.created_at.desc(),
    )


async def _review_suggestion(
    db: AsyncSession, user: User, suggestion_id: str, status: SuggestionStatus
) -> AssetSuggestion:
    suggestion = await db.scalar(
        select(AssetSuggestion).where(
            AssetSuggestion.id == suggestion_id,
            AssetSuggestion.organization_id == user.organization_id,
            AssetSuggestion.status == SuggestionStatus.PENDING,
        )
    )
    if not suggestion:
        raise HTTPException(404, "Pending suggestion not found")
    suggestion.status = status
    suggestion.reviewed_by = user.id
    suggestion.reviewed_at = datetime.now(timezone.utc)
    await write_audit(
        db, user, f"asset_suggestion.{status.value}", "asset_suggestion", suggestion.id
    )
    await db.commit()
    asset_suggestions.labels(result=status.value).inc()
    return suggestion


@router.post("/asset-suggestions/{suggestion_id}/accept")
async def accept_suggestion(
    suggestion_id: str,
    user: User = Depends(require_permission("asset_suggestions.review")),
    db: AsyncSession = Depends(get_db),
):
    return await _review_suggestion(db, user, suggestion_id, SuggestionStatus.ACCEPTED)


@router.post("/asset-suggestions/{suggestion_id}/reject")
async def reject_suggestion(
    suggestion_id: str,
    user: User = Depends(require_permission("asset_suggestions.review")),
    db: AsyncSession = Depends(get_db),
):
    return await _review_suggestion(db, user, suggestion_id, SuggestionStatus.REJECTED)


@router.get("/network-policies")
async def list_network_policies(
    user: User = Depends(require_permission("network_policies.read")),
    db: AsyncSession = Depends(get_db),
):
    profiles = list(
        (
            await db.scalars(
                select(ScanProfile).where(
                    ScanProfile.organization_id == user.organization_id,
                    ScanProfile.network_access.is_(True),
                    ScanProfile.enabled.is_(True),
                )
            )
        ).all()
    )
    return [
        {
            "profile_id": profile.id,
            "profile_name": profile.name,
            **build_network_policy(
                category=profile.category,
                profile_timeout=profile.timeout_seconds,
                laboratory_mode=False,
            ).model_dump(mode="json"),
        }
        for profile in profiles
    ]


@router.get("/jobs/{job_id}/network-summary")
async def get_job_network_summary(
    job_id: str,
    user: User = Depends(require_permission("network_policies.read")),
    db: AsyncSession = Depends(get_db),
):
    job = await db.scalar(
        select(ScanJob).where(
            ScanJob.id == job_id,
            ScanJob.organization_id == user.organization_id,
        )
    )
    if not job:
        raise HTTPException(404, "Job not found")
    return job.result_summary.get("network") or {
        "network_used": False,
        "adapter_code": job.adapter_code,
    }
