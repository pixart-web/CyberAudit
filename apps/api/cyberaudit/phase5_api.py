"""Tenant-isolated Application Security API.

The endpoints in this module only ingest declared metadata or bounded files. They
never clone repositories, execute submitted code, resolve remote references, or
send assessment traffic directly.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Literal

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile
from pydantic import BaseModel, ConfigDict, Field, HttpUrl
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from cyberaudit.appsec_services import (
    AppSecRiskContext,
    calculate_appsec_risk,
    evaluate_security_gate,
    parse_api_specification,
    parse_cyclonedx_json,
)
from cyberaudit.audit import write_audit
from cyberaudit.db import get_db
from cyberaudit.models import Client, Finding, User, utcnow
from cyberaudit.phase4_models import Environment
from cyberaudit.phase5_models import (
    ApiAsset,
    ApiEndpoint,
    ApiSpecificationImport,
    ApplicationAsset,
    AppSecException,
    AppSecRemediation,
    AppSecScore,
    CodeRepository,
    ComponentReachability,
    SbomComponent,
    SbomDependency,
    SecretObservation,
    SecurityGateEvaluation,
    SecurityGatePolicy,
    SoftwareBillOfMaterials,
    SoftwareRelease,
)
from cyberaudit.security import require_permission
from cyberaudit.storage import LocalStorage

router = APIRouter(prefix="/api/v1", tags=["application-security"])
storage = LocalStorage()


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ApplicationPayload(StrictModel):
    client_id: str
    environment_id: str
    name: str = Field(min_length=2, max_length=180)
    description: str = Field(default="", max_length=5000)
    application_type: str = Field(default="web", max_length=60)
    architecture_type: str = Field(default="unknown", max_length=60)
    lifecycle_status: str = Field(default="development", max_length=40)
    internet_exposed: bool = False
    internal_only: bool = True
    base_urls: list[HttpUrl] = Field(default_factory=list, max_length=20)
    repository_urls: list[HttpUrl] = Field(default_factory=list, max_length=20)
    owners: list[str] = Field(default_factory=list, max_length=30)
    technical_owner: str | None = Field(default=None, max_length=180)
    business_owner: str | None = Field(default=None, max_length=180)
    data_classification: str = Field(default="internal", max_length=40)
    business_criticality: Literal["low", "medium", "high", "critical"] = "medium"
    authentication_type: str = Field(default="unknown", max_length=60)
    authorization_model: str = Field(default="unknown", max_length=80)
    technology_stack: list[dict[str, Any]] = Field(default_factory=list, max_length=100)
    tags: list[str] = Field(default_factory=list, max_length=50)


class ApplicationPatch(StrictModel):
    name: str | None = Field(default=None, min_length=2, max_length=180)
    description: str | None = Field(default=None, max_length=5000)
    lifecycle_status: str | None = Field(default=None, max_length=40)
    internet_exposed: bool | None = None
    internal_only: bool | None = None
    owners: list[str] | None = Field(default=None, max_length=30)
    technical_owner: str | None = Field(default=None, max_length=180)
    business_owner: str | None = Field(default=None, max_length=180)
    data_classification: str | None = Field(default=None, max_length=40)
    business_criticality: Literal["low", "medium", "high", "critical"] | None = None
    tags: list[str] | None = Field(default=None, max_length=50)


class ApiPayload(StrictModel):
    application_id: str
    environment_id: str
    name: str = Field(min_length=2, max_length=180)
    description: str = Field(default="", max_length=5000)
    api_type: str = Field(default="rest", max_length=40)
    visibility: str = Field(default="internal", max_length=30)
    base_url: HttpUrl
    version: str | None = Field(default=None, max_length=80)
    authentication_type: str = Field(default="unknown", max_length=60)
    authorization_model: str = Field(default="unknown", max_length=80)
    data_classification: str = Field(default="internal", max_length=40)
    business_criticality: Literal["low", "medium", "high", "critical"] = "medium"
    owner: str | None = Field(default=None, max_length=180)
    lifecycle_status: str = Field(default="development", max_length=40)
    tags: list[str] = Field(default_factory=list, max_length=50)


class RepositoryPayload(StrictModel):
    application_id: str | None = None
    provider: str = Field(max_length=60)
    repository_identifier: str = Field(min_length=2, max_length=300)
    repository_url: HttpUrl
    name: str = Field(min_length=2, max_length=200)
    default_branch: str = Field(default="main", max_length=160)
    visibility: Literal["private", "internal", "public"] = "private"
    owner_team: str | None = Field(default=None, max_length=180)
    language_summary: dict[str, float] = Field(default_factory=dict)


class ReleasePayload(StrictModel):
    application_id: str
    repository_id: str | None = None
    version: str = Field(min_length=1, max_length=160)
    commit_hash: str | None = Field(default=None, max_length=128)
    branch: str | None = Field(default=None, max_length=180)
    tag: str | None = Field(default=None, max_length=180)
    build_id: str | None = Field(default=None, max_length=180)
    artifact_identifier: str = Field(min_length=1, max_length=500)
    artifact_hash: str = Field(min_length=32, max_length=128)
    image_digest: str | None = Field(default=None, max_length=200)
    environment_id: str | None = None
    status: str = Field(default="built", max_length=40)
    signed: bool = False
    signature_verified: bool = False
    provenance_available: bool = False
    provenance_verified: bool = False


class GatePayload(StrictModel):
    name: str = Field(min_length=2, max_length=180)
    description: str = Field(default="", max_length=5000)
    scope_selector: dict[str, Any] = Field(default_factory=dict)
    applies_to: str = Field(default="release", max_length=60)
    environment: str = Field(default="production", max_length=60)
    minimum_appsec_score: float = Field(default=70, ge=0, le=100)
    maximum_critical_findings: int = Field(default=0, ge=0, le=10000)
    maximum_high_findings: int = Field(default=0, ge=0, le=10000)
    block_known_exploited: bool = True
    block_confirmed_secrets: bool = True
    block_unsigned_artifacts: bool = False
    require_sbom: bool = True
    require_sast: bool = False
    require_sca: bool = True
    require_iac_scan: bool = False
    require_container_scan: bool = False
    maximum_scan_age: int = Field(default=30, ge=1, le=365)
    exceptions_allowed: bool = True
    approval_required: bool = False
    enabled: bool = True


class GateEvaluationPayload(StrictModel):
    application_id: str
    release_id: str | None = None


class ExceptionPayload(StrictModel):
    application_id: str
    finding_id: str | None = None
    release_id: str | None = None
    exception_type: str = Field(max_length=60)
    reason: str = Field(min_length=10, max_length=5000)
    business_justification: str = Field(min_length=10, max_length=5000)
    compensating_controls: list[str] = Field(default_factory=list, max_length=50)
    expires_at: datetime
    review_date: datetime


class ReviewPayload(StrictModel):
    notes: str = Field(default="", max_length=5000)


class RemediationPayload(StrictModel):
    finding_id: str
    application_id: str
    repository_id: str | None = None
    owner_team: str = Field(min_length=2, max_length=180)
    assignee: str | None = Field(default=None, max_length=180)
    status: str = Field(default="open", max_length=40)
    priority: str = Field(default="normal", max_length=30)
    target_release: str | None = Field(default=None, max_length=160)
    due_date: datetime | None = None
    remediation_plan: str = Field(min_length=10, max_length=10000)
    validation_plan: str = Field(min_length=10, max_length=10000)


async def _page(
    db: AsyncSession,
    model: Any,
    where: list[Any],
    page: int,
    page_size: int,
    order: Any,
) -> dict[str, Any]:
    total = await db.scalar(select(func.count()).select_from(model).where(*where))
    rows = list(
        (
            await db.scalars(
                select(model)
                .where(*where)
                .order_by(order)
                .offset((page - 1) * page_size)
                .limit(page_size)
            )
        ).all()
    )
    return {"items": rows, "total": total or 0, "page": page, "page_size": page_size}


async def _tenant_row(db: AsyncSession, model: Any, row_id: str, organization_id: str) -> Any:
    row = await db.scalar(
        select(model).where(model.id == row_id, model.organization_id == organization_id)
    )
    if not row:
        raise HTTPException(404, "Resource not found")
    return row


async def _application(
    db: AsyncSession, application_id: str, organization_id: str
) -> ApplicationAsset:
    return await _tenant_row(db, ApplicationAsset, application_id, organization_id)


@router.get("/applications")
async def list_applications(
    search: str | None = Query(default=None, max_length=100),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    user: User = Depends(require_permission("applications.read")),
    db: AsyncSession = Depends(get_db),
):
    where = [ApplicationAsset.organization_id == user.organization_id]
    if search:
        where.append(
            or_(
                ApplicationAsset.name.ilike(f"%{search}%"),
                ApplicationAsset.description.ilike(f"%{search}%"),
            )
        )
    return await _page(db, ApplicationAsset, where, page, page_size, ApplicationAsset.name)


@router.post("/applications", status_code=201)
async def create_application(
    payload: ApplicationPayload,
    user: User = Depends(require_permission("applications.manage")),
    db: AsyncSession = Depends(get_db),
):
    if not await db.scalar(
        select(Client.id).where(
            Client.id == payload.client_id, Client.organization_id == user.organization_id
        )
    ):
        raise HTTPException(404, "Client not found")
    if not await db.scalar(
        select(Environment.id).where(
            Environment.id == payload.environment_id,
            Environment.organization_id == user.organization_id,
        )
    ):
        raise HTTPException(404, "Environment not found")
    values = payload.model_dump(mode="json")
    row = ApplicationAsset(
        organization_id=user.organization_id,
        **values,
        source="manual",
    )
    db.add(row)
    await write_audit(db, user, "application.created", "application", row.id)
    await db.commit()
    await db.refresh(row)
    return row


@router.get("/applications/{application_id}")
async def get_application(
    application_id: str,
    user: User = Depends(require_permission("applications.read")),
    db: AsyncSession = Depends(get_db),
):
    return await _application(db, application_id, user.organization_id)


@router.patch("/applications/{application_id}")
async def patch_application(
    application_id: str,
    payload: ApplicationPatch,
    user: User = Depends(require_permission("applications.manage")),
    db: AsyncSession = Depends(get_db),
):
    row = await _application(db, application_id, user.organization_id)
    for key, value in payload.model_dump(exclude_unset=True).items():
        setattr(row, key, value)
    await write_audit(db, user, "application.updated", "application", row.id)
    await db.commit()
    await db.refresh(row)
    return row


@router.get("/applications/{application_id}/overview")
async def application_overview(
    application_id: str,
    user: User = Depends(require_permission("applications.read")),
    db: AsyncSession = Depends(get_db),
):
    app = await _application(db, application_id, user.organization_id)
    counts: dict[str, int] = {}
    for name, model, field in (
        ("apis", ApiAsset, ApiAsset.application_id),
        ("repositories", CodeRepository, CodeRepository.application_id),
        ("releases", SoftwareRelease, SoftwareRelease.application_id),
        ("secrets", SecretObservation, SecretObservation.application_id),
    ):
        counts[name] = (
            await db.scalar(
                select(func.count())
                .select_from(model)
                .where(
                    model.organization_id == user.organization_id,
                    field == application_id,
                )
            )
            or 0
        )
    findings = (
        await db.scalar(
            select(func.count())
            .select_from(Finding)
            .where(
                Finding.organization_id == user.organization_id,
                Finding.application_id == application_id,
            )
        )
        or 0
    )
    return {"application": app, "counts": {**counts, "findings": findings}}


@router.get("/applications/{application_id}/risk")
async def application_risk(
    application_id: str,
    user: User = Depends(require_permission("appsec_risk.read")),
    db: AsyncSession = Depends(get_db),
):
    app = await _application(db, application_id, user.organization_id)
    context = AppSecRiskContext(
        public_exposure=app.internet_exposed,
        data_sensitivity={"public": 10, "internal": 40, "confidential": 75, "restricted": 95}.get(
            app.data_classification, 50
        ),
        application_criticality={"low": 20, "medium": 50, "high": 75, "critical": 95}.get(
            app.business_criticality, 50
        ),
        confidence=app.confidence,
    )
    return calculate_appsec_risk(context)


@router.get("/applications/{application_id}/scores")
async def application_scores(
    application_id: str,
    user: User = Depends(require_permission("appsec_risk.read")),
    db: AsyncSession = Depends(get_db),
):
    await _application(db, application_id, user.organization_id)
    return list(
        (
            await db.scalars(
                select(AppSecScore)
                .where(
                    AppSecScore.organization_id == user.organization_id,
                    AppSecScore.entity_type == "application",
                    AppSecScore.entity_id == application_id,
                )
                .order_by(AppSecScore.calculated_at.desc())
            )
        ).all()
    )


@router.get("/applications/{application_id}/apis")
@router.get(
    "/applications/{application_id}/APIs",
    include_in_schema=False,
)
async def application_apis(
    application_id: str,
    user: User = Depends(require_permission("apis.read")),
    db: AsyncSession = Depends(get_db),
):
    await _application(db, application_id, user.organization_id)
    return list(
        (
            await db.scalars(
                select(ApiAsset)
                .where(
                    ApiAsset.organization_id == user.organization_id,
                    ApiAsset.application_id == application_id,
                )
                .order_by(ApiAsset.name)
            )
        ).all()
    )


@router.get("/applications/{application_id}/repositories")
async def application_repositories(
    application_id: str,
    user: User = Depends(require_permission("repositories.read")),
    db: AsyncSession = Depends(get_db),
):
    await _application(db, application_id, user.organization_id)
    return list(
        (
            await db.scalars(
                select(CodeRepository)
                .where(
                    CodeRepository.organization_id == user.organization_id,
                    CodeRepository.application_id == application_id,
                )
                .order_by(CodeRepository.name)
            )
        ).all()
    )


@router.get("/applications/{application_id}/releases")
async def application_releases(
    application_id: str,
    user: User = Depends(require_permission("releases.read")),
    db: AsyncSession = Depends(get_db),
):
    await _application(db, application_id, user.organization_id)
    return list(
        (
            await db.scalars(
                select(SoftwareRelease)
                .where(
                    SoftwareRelease.organization_id == user.organization_id,
                    SoftwareRelease.application_id == application_id,
                )
                .order_by(SoftwareRelease.created_at.desc())
            )
        ).all()
    )


@router.get("/applications/{application_id}/components")
async def application_components(
    application_id: str,
    user: User = Depends(require_permission("sboms.read")),
    db: AsyncSession = Depends(get_db),
):
    await _application(db, application_id, user.organization_id)
    return list(
        (
            await db.scalars(
                select(SbomComponent)
                .join(
                    SoftwareBillOfMaterials,
                    SoftwareBillOfMaterials.id == SbomComponent.sbom_id,
                )
                .where(
                    SoftwareBillOfMaterials.organization_id == user.organization_id,
                    SoftwareBillOfMaterials.application_id == application_id,
                )
                .order_by(SbomComponent.name)
            )
        ).all()
    )


@router.get("/applications/{application_id}/findings")
async def application_findings(
    application_id: str,
    user: User = Depends(require_permission("findings.read")),
    db: AsyncSession = Depends(get_db),
):
    await _application(db, application_id, user.organization_id)
    return list(
        (
            await db.scalars(
                select(Finding)
                .where(
                    Finding.organization_id == user.organization_id,
                    Finding.application_id == application_id,
                )
                .order_by(Finding.last_seen_at.desc())
            )
        ).all()
    )


@router.get("/applications/{application_id}/coverage")
async def application_coverage(
    application_id: str,
    user: User = Depends(require_permission("appsec_risk.read")),
    db: AsyncSession = Depends(get_db),
):
    app = await _application(db, application_id, user.organization_id)
    facts = {
        "web": app.last_assessed_at is not None,
        "api": bool(
            await db.scalar(
                select(ApiAsset.last_assessed_at).where(
                    ApiAsset.organization_id == user.organization_id,
                    ApiAsset.application_id == app.id,
                    ApiAsset.last_assessed_at.is_not(None),
                )
            )
        ),
        "sbom": bool(
            await db.scalar(
                select(SoftwareBillOfMaterials.id).where(
                    SoftwareBillOfMaterials.organization_id == user.organization_id,
                    SoftwareBillOfMaterials.application_id == app.id,
                    SoftwareBillOfMaterials.validated.is_(True),
                )
            )
        ),
    }
    return {
        "controls": facts,
        "coverage_percentage": round(
            sum(1 for covered in facts.values() if covered) / len(facts) * 100, 2
        ),
    }


@router.get("/applications/{application_id}/timeline")
async def application_timeline(
    application_id: str,
    user: User = Depends(require_permission("applications.read")),
    db: AsyncSession = Depends(get_db),
):
    app = await _application(db, application_id, user.organization_id)
    releases = list(
        (
            await db.scalars(
                select(SoftwareRelease)
                .where(
                    SoftwareRelease.organization_id == user.organization_id,
                    SoftwareRelease.application_id == app.id,
                )
                .order_by(SoftwareRelease.created_at.desc())
                .limit(25)
            )
        ).all()
    )
    return {
        "items": [
            {
                "type": "release",
                "id": row.id,
                "at": row.released_at or row.created_at,
                "label": row.version,
            }
            for row in releases
        ]
    }


@router.get("/applications/{application_id}/graph")
async def application_graph(
    application_id: str,
    user: User = Depends(require_permission("applications.read")),
    db: AsyncSession = Depends(get_db),
):
    app = await _application(db, application_id, user.organization_id)
    apis = list(
        (
            await db.scalars(
                select(ApiAsset).where(
                    ApiAsset.organization_id == user.organization_id,
                    ApiAsset.application_id == app.id,
                )
            )
        ).all()
    )
    repositories = list(
        (
            await db.scalars(
                select(CodeRepository).where(
                    CodeRepository.organization_id == user.organization_id,
                    CodeRepository.application_id == app.id,
                )
            )
        ).all()
    )
    return {
        "nodes": [
            {"id": app.id, "type": "application", "label": app.name},
            *[{"id": row.id, "type": "api", "label": row.name} for row in apis],
            *[{"id": row.id, "type": "repository", "label": row.name} for row in repositories],
        ],
        "edges": [
            *[{"source": app.id, "target": row.id, "type": "exposes"} for row in apis],
            *[{"source": app.id, "target": row.id, "type": "built_from"} for row in repositories],
        ],
    }


@router.get("/apis")
async def list_apis(
    application_id: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    user: User = Depends(require_permission("apis.read")),
    db: AsyncSession = Depends(get_db),
):
    where = [ApiAsset.organization_id == user.organization_id]
    if application_id:
        where.append(ApiAsset.application_id == application_id)
    return await _page(db, ApiAsset, where, page, page_size, ApiAsset.name)


@router.post("/apis", status_code=201)
async def create_api(
    payload: ApiPayload,
    user: User = Depends(require_permission("apis.manage")),
    db: AsyncSession = Depends(get_db),
):
    await _application(db, payload.application_id, user.organization_id)
    environment = await _tenant_row(db, Environment, payload.environment_id, user.organization_id)
    app = await _application(db, payload.application_id, user.organization_id)
    if environment.id != app.environment_id:
        raise HTTPException(422, "API environment must match its application")
    row = ApiAsset(
        organization_id=user.organization_id,
        **payload.model_dump(mode="json"),
        source="manual",
    )
    db.add(row)
    await write_audit(db, user, "api.created", "api", row.id)
    await db.commit()
    await db.refresh(row)
    return row


@router.patch("/apis/{api_id}")
async def patch_api(
    api_id: str,
    payload: ApiPayload,
    user: User = Depends(require_permission("apis.manage")),
    db: AsyncSession = Depends(get_db),
):
    row = await _tenant_row(db, ApiAsset, api_id, user.organization_id)
    await _application(db, payload.application_id, user.organization_id)
    await _tenant_row(db, Environment, payload.environment_id, user.organization_id)
    for key, value in payload.model_dump(mode="json").items():
        setattr(row, key, value)
    await write_audit(db, user, "api.updated", "api", row.id)
    await db.commit()
    await db.refresh(row)
    return row


@router.get("/apis/{api_id}")
async def get_api(
    api_id: str,
    user: User = Depends(require_permission("apis.read")),
    db: AsyncSession = Depends(get_db),
):
    return await _tenant_row(db, ApiAsset, api_id, user.organization_id)


@router.get("/apis/{api_id}/endpoints")
async def api_endpoints(
    api_id: str,
    user: User = Depends(require_permission("apis.read")),
    db: AsyncSession = Depends(get_db),
):
    await _tenant_row(db, ApiAsset, api_id, user.organization_id)
    return list(
        (
            await db.scalars(
                select(ApiEndpoint)
                .where(
                    ApiEndpoint.organization_id == user.organization_id,
                    ApiEndpoint.api_id == api_id,
                )
                .order_by(ApiEndpoint.normalized_path, ApiEndpoint.method)
            )
        ).all()
    )


@router.get("/apis/{api_id}/findings")
async def api_findings(
    api_id: str,
    user: User = Depends(require_permission("findings.read")),
    db: AsyncSession = Depends(get_db),
):
    await _tenant_row(db, ApiAsset, api_id, user.organization_id)
    return list(
        (
            await db.scalars(
                select(Finding).where(
                    Finding.organization_id == user.organization_id,
                    Finding.api_id == api_id,
                )
            )
        ).all()
    )


@router.get("/apis/{api_id}/coverage")
async def api_coverage(
    api_id: str,
    user: User = Depends(require_permission("appsec_risk.read")),
    db: AsyncSession = Depends(get_db),
):
    api = await _tenant_row(db, ApiAsset, api_id, user.organization_id)
    endpoint_count = (
        await db.scalar(
            select(func.count())
            .select_from(ApiEndpoint)
            .where(
                ApiEndpoint.organization_id == user.organization_id,
                ApiEndpoint.api_id == api.id,
            )
        )
        or 0
    )
    return {
        "specification_imported": bool(api.specification_hash),
        "endpoint_count": endpoint_count,
        "last_assessed_at": api.last_assessed_at,
    }


@router.get("/api-endpoints/{endpoint_id}")
async def get_api_endpoint(
    endpoint_id: str,
    user: User = Depends(require_permission("apis.read")),
    db: AsyncSession = Depends(get_db),
):
    return await _tenant_row(db, ApiEndpoint, endpoint_id, user.organization_id)


@router.post("/api-specifications", status_code=201)
@router.post("/api-specifications/import", status_code=201, include_in_schema=False)
async def import_api_specification(
    application_id: str = Form(...),
    api_id: str | None = Form(default=None),
    upload: UploadFile = File(...),
    user: User = Depends(require_permission("api_specifications.import")),
    db: AsyncSession = Depends(get_db),
):
    await _application(db, application_id, user.organization_id)
    if api_id:
        api = await _tenant_row(db, ApiAsset, api_id, user.organization_id)
        if api.application_id != application_id:
            raise HTTPException(422, "API belongs to another application")
    try:
        key, digest, _ = await storage.save_private_file(
            upload,
            allowed_extensions={".json"},
            allowed_mime_types={"application/json"},
            maximum_bytes=10 * 1024 * 1024,
        )
        content = storage.read_private_file(key, 10 * 1024 * 1024)
        preview = parse_api_specification(content)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    row = ApiSpecificationImport(
        organization_id=user.organization_id,
        application_id=application_id,
        api_id=api_id,
        filename=(upload.filename or "specification.json")[:255],
        storage_key=key,
        content_hash=digest,
        specification_type=preview.specification_type,
        status="previewed",
        preview=preview.model_dump(mode="json"),
        validation_errors=[],
        uploaded_by=user.id,
    )
    db.add(row)
    await write_audit(
        db,
        user,
        "api_specification.uploaded",
        "api_specification_import",
        row.id,
        metadata={"sha256": digest, "endpoint_count": len(preview.endpoints)},
    )
    await db.commit()
    await db.refresh(row)
    return row


@router.get("/api-specifications/{import_id}")
async def get_api_specification_import(
    import_id: str,
    user: User = Depends(require_permission("api_specifications.import")),
    db: AsyncSession = Depends(get_db),
):
    return await _tenant_row(db, ApiSpecificationImport, import_id, user.organization_id)


@router.post("/api-specifications/{import_id}/preview")
async def preview_api_specification(
    import_id: str,
    user: User = Depends(require_permission("api_specifications.import")),
    db: AsyncSession = Depends(get_db),
):
    row = await _tenant_row(db, ApiSpecificationImport, import_id, user.organization_id)
    return row.preview


@router.post("/api-specifications/{import_id}/confirm")
async def confirm_api_specification(
    import_id: str,
    user: User = Depends(require_permission("api_specifications.import")),
    db: AsyncSession = Depends(get_db),
):
    row = await _tenant_row(db, ApiSpecificationImport, import_id, user.organization_id)
    if row.status != "previewed":
        raise HTTPException(409, "Import is not ready for confirmation")
    preview = row.preview
    if row.api_id:
        api = await _tenant_row(db, ApiAsset, row.api_id, user.organization_id)
    else:
        app = await _application(db, row.application_id, user.organization_id)
        api = ApiAsset(
            organization_id=user.organization_id,
            application_id=app.id,
            environment_id=app.environment_id,
            name=str(preview["title"])[:180],
            description="Imported from an offline API specification.",
            api_type="rest",
            visibility="internal",
            base_url=str(preview.get("base_url") or "https://invalid.local"),
            version=str(preview["version"])[:80],
            specification_type=str(preview["specification_type"]),
            specification_hash=row.content_hash,
            source="specification",
        )
        db.add(api)
        await db.flush()
        row.api_id = api.id
    existing = set(
        (
            await db.execute(
                select(ApiEndpoint.method, ApiEndpoint.normalized_path).where(
                    ApiEndpoint.organization_id == user.organization_id,
                    ApiEndpoint.api_id == api.id,
                )
            )
        ).all()
    )
    created = 0
    for item in preview.get("endpoints", []):
        key = (item["method"], item["normalized_path"])
        if key in existing:
            continue
        db.add(
            ApiEndpoint(
                organization_id=user.organization_id,
                api_id=api.id,
                **item,
            )
        )
        created += 1
    api.specification_hash = row.content_hash
    api.specification_type = row.specification_type
    row.status = "confirmed"
    await write_audit(
        db,
        user,
        "api_specification.confirmed",
        "api_specification_import",
        row.id,
        metadata={"endpoints_created": created},
    )
    await db.commit()
    return {"id": row.id, "api_id": api.id, "endpoints_created": created}


@router.post("/api-specifications/{import_id}/cancel")
async def cancel_api_specification(
    import_id: str,
    user: User = Depends(require_permission("api_specifications.import")),
    db: AsyncSession = Depends(get_db),
):
    row = await _tenant_row(db, ApiSpecificationImport, import_id, user.organization_id)
    if row.status == "confirmed":
        raise HTTPException(409, "Confirmed import cannot be cancelled")
    row.status = "cancelled"
    await write_audit(db, user, "api_specification.cancelled", "api_specification_import", row.id)
    await db.commit()
    return {"id": row.id, "status": row.status}


@router.get("/repositories")
async def list_repositories(
    application_id: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    user: User = Depends(require_permission("repositories.read")),
    db: AsyncSession = Depends(get_db),
):
    where = [CodeRepository.organization_id == user.organization_id]
    if application_id:
        where.append(CodeRepository.application_id == application_id)
    return await _page(db, CodeRepository, where, page, page_size, CodeRepository.name)


@router.post("/repositories", status_code=201)
async def create_repository(
    payload: RepositoryPayload,
    user: User = Depends(require_permission("repositories.manage")),
    db: AsyncSession = Depends(get_db),
):
    if payload.application_id:
        await _application(db, payload.application_id, user.organization_id)
    row = CodeRepository(organization_id=user.organization_id, **payload.model_dump(mode="json"))
    db.add(row)
    await write_audit(db, user, "repository.created", "repository", row.id)
    await db.commit()
    await db.refresh(row)
    return row


@router.patch("/repositories/{repository_id}")
async def patch_repository(
    repository_id: str,
    payload: RepositoryPayload,
    user: User = Depends(require_permission("repositories.manage")),
    db: AsyncSession = Depends(get_db),
):
    row = await _tenant_row(db, CodeRepository, repository_id, user.organization_id)
    if payload.application_id:
        await _application(db, payload.application_id, user.organization_id)
    for key, value in payload.model_dump(mode="json").items():
        setattr(row, key, value)
    await write_audit(db, user, "repository.updated", "repository", row.id)
    await db.commit()
    await db.refresh(row)
    return row


@router.get("/repositories/{repository_id}")
async def get_repository(
    repository_id: str,
    user: User = Depends(require_permission("repositories.read")),
    db: AsyncSession = Depends(get_db),
):
    return await _tenant_row(db, CodeRepository, repository_id, user.organization_id)


@router.get("/repositories/{repository_id}/secrets")
async def repository_secrets(
    repository_id: str,
    user: User = Depends(require_permission("secrets.read")),
    db: AsyncSession = Depends(get_db),
):
    await _tenant_row(db, CodeRepository, repository_id, user.organization_id)
    rows = list(
        (
            await db.scalars(
                select(SecretObservation).where(
                    SecretObservation.organization_id == user.organization_id,
                    SecretObservation.repository_id == repository_id,
                )
            )
        ).all()
    )
    # Never return raw secret material. The database model does not have a field
    # capable of storing it.
    return [
        {
            "id": item.id,
            "secret_type": item.secret_type,
            "fingerprint": item.fingerprint,
            "location": item.location,
            "length": item.length,
            "masked_prefix": item.masked_prefix,
            "status": item.status,
            "confidence": item.confidence,
            "created_at": item.created_at,
        }
        for item in rows
    ]


@router.get("/repositories/{repository_id}/findings")
async def repository_findings(
    repository_id: str,
    user: User = Depends(require_permission("findings.read")),
    db: AsyncSession = Depends(get_db),
):
    await _tenant_row(db, CodeRepository, repository_id, user.organization_id)
    return list(
        (
            await db.scalars(
                select(Finding).where(
                    Finding.organization_id == user.organization_id,
                    Finding.repository_id == repository_id,
                )
            )
        ).all()
    )


@router.get("/repositories/{repository_id}/components")
async def repository_components(
    repository_id: str,
    user: User = Depends(require_permission("sboms.read")),
    db: AsyncSession = Depends(get_db),
):
    await _tenant_row(db, CodeRepository, repository_id, user.organization_id)
    return list(
        (
            await db.scalars(
                select(SbomComponent)
                .join(
                    SoftwareBillOfMaterials,
                    SoftwareBillOfMaterials.id == SbomComponent.sbom_id,
                )
                .where(
                    SoftwareBillOfMaterials.organization_id == user.organization_id,
                    SoftwareBillOfMaterials.repository_id == repository_id,
                )
            )
        ).all()
    )


@router.get("/repositories/{repository_id}/releases")
async def repository_releases(
    repository_id: str,
    user: User = Depends(require_permission("releases.read")),
    db: AsyncSession = Depends(get_db),
):
    await _tenant_row(db, CodeRepository, repository_id, user.organization_id)
    return list(
        (
            await db.scalars(
                select(SoftwareRelease)
                .where(
                    SoftwareRelease.organization_id == user.organization_id,
                    SoftwareRelease.repository_id == repository_id,
                )
                .order_by(SoftwareRelease.created_at.desc())
            )
        ).all()
    )


@router.get("/components")
async def list_components(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    user: User = Depends(require_permission("sboms.read")),
    db: AsyncSession = Depends(get_db),
):
    tenant_sboms = select(SoftwareBillOfMaterials.id).where(
        SoftwareBillOfMaterials.organization_id == user.organization_id
    )
    return await _page(
        db,
        SbomComponent,
        [SbomComponent.sbom_id.in_(tenant_sboms)],
        page,
        page_size,
        SbomComponent.name,
    )


@router.get("/secrets")
async def list_secret_observations(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    user: User = Depends(require_permission("secrets.read")),
    db: AsyncSession = Depends(get_db),
):
    response = await _page(
        db,
        SecretObservation,
        [SecretObservation.organization_id == user.organization_id],
        page,
        page_size,
        SecretObservation.created_at.desc(),
    )
    response["items"] = [
        {
            "id": item.id,
            "repository_id": item.repository_id,
            "secret_type": item.secret_type,
            "fingerprint": item.fingerprint,
            "location": item.location,
            "length": item.length,
            "masked_prefix": item.masked_prefix,
            "status": item.status,
            "confidence": item.confidence,
            "created_at": item.created_at,
        }
        for item in response["items"]
    ]
    return response


@router.get("/releases")
async def list_releases(
    application_id: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    user: User = Depends(require_permission("releases.read")),
    db: AsyncSession = Depends(get_db),
):
    where = [SoftwareRelease.organization_id == user.organization_id]
    if application_id:
        where.append(SoftwareRelease.application_id == application_id)
    return await _page(
        db, SoftwareRelease, where, page, page_size, SoftwareRelease.created_at.desc()
    )


@router.post("/releases", status_code=201)
async def create_release(
    payload: ReleasePayload,
    user: User = Depends(require_permission("releases.manage")),
    db: AsyncSession = Depends(get_db),
):
    await _application(db, payload.application_id, user.organization_id)
    if payload.repository_id:
        await _tenant_row(db, CodeRepository, payload.repository_id, user.organization_id)
    if payload.environment_id:
        await _tenant_row(db, Environment, payload.environment_id, user.organization_id)
    row = SoftwareRelease(organization_id=user.organization_id, **payload.model_dump(mode="json"))
    db.add(row)
    await write_audit(db, user, "release.created", "release", row.id)
    await db.commit()
    await db.refresh(row)
    return row


@router.get("/releases/{release_id}")
async def get_release(
    release_id: str,
    user: User = Depends(require_permission("releases.read")),
    db: AsyncSession = Depends(get_db),
):
    return await _tenant_row(db, SoftwareRelease, release_id, user.organization_id)


@router.get("/releases/{release_id}/risk")
async def release_risk(
    release_id: str,
    user: User = Depends(require_permission("appsec_risk.read")),
    db: AsyncSession = Depends(get_db),
):
    release = await _tenant_row(db, SoftwareRelease, release_id, user.organization_id)
    findings = (
        await db.scalar(
            select(func.count())
            .select_from(Finding)
            .where(
                Finding.organization_id == user.organization_id,
                Finding.release_id == release.id,
                Finding.status.in_(["open", "confirmed"]),
            )
        )
        or 0
    )
    return {
        "release_id": release.id,
        "open_findings": findings,
        "artifact_signed": release.signature_verified,
        "provenance_verified": release.provenance_verified,
        "sbom_present": bool(release.sbom_id),
    }


@router.get("/releases/{release_id}/findings")
async def release_findings(
    release_id: str,
    user: User = Depends(require_permission("findings.read")),
    db: AsyncSession = Depends(get_db),
):
    await _tenant_row(db, SoftwareRelease, release_id, user.organization_id)
    return list(
        (
            await db.scalars(
                select(Finding).where(
                    Finding.organization_id == user.organization_id,
                    Finding.release_id == release_id,
                )
            )
        ).all()
    )


@router.get("/releases/{release_id}/gate-evaluations")
async def release_gate_evaluations(
    release_id: str,
    user: User = Depends(require_permission("security_gates.read")),
    db: AsyncSession = Depends(get_db),
):
    await _tenant_row(db, SoftwareRelease, release_id, user.organization_id)
    return list(
        (
            await db.scalars(
                select(SecurityGateEvaluation)
                .where(
                    SecurityGateEvaluation.organization_id == user.organization_id,
                    SecurityGateEvaluation.release_id == release_id,
                )
                .order_by(SecurityGateEvaluation.evaluated_at.desc())
            )
        ).all()
    )


@router.post("/sboms", status_code=201)
@router.post("/sboms/import", status_code=201, include_in_schema=False)
async def import_sbom(
    application_id: str = Form(...),
    release_id: str | None = Form(default=None),
    repository_id: str | None = Form(default=None),
    upload: UploadFile = File(...),
    user: User = Depends(require_permission("sboms.import")),
    db: AsyncSession = Depends(get_db),
):
    await _application(db, application_id, user.organization_id)
    if release_id:
        release = await _tenant_row(db, SoftwareRelease, release_id, user.organization_id)
        if release.application_id != application_id:
            raise HTTPException(422, "Release belongs to another application")
    if repository_id:
        await _tenant_row(db, CodeRepository, repository_id, user.organization_id)
    try:
        key, digest, _ = await storage.save_private_file(
            upload,
            allowed_extensions={".json"},
            allowed_mime_types={"application/json"},
            maximum_bytes=10 * 1024 * 1024,
        )
        preview = parse_cyclonedx_json(storage.read_private_file(key, 10 * 1024 * 1024))
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    row = SoftwareBillOfMaterials(
        organization_id=user.organization_id,
        application_id=application_id,
        release_id=release_id,
        repository_id=repository_id,
        format=preview.format,
        specification_version=preview.specification_version,
        serial_number=preview.serial_number,
        document_hash=digest,
        component_count=len(preview.components),
        dependency_count=sum(len(item["depends_on"]) for item in preview.dependencies),
        direct_dependency_count=0,
        transitive_dependency_count=0,
        generated_by="import",
        imported=True,
        validated=not preview.warnings,
        validation_errors=preview.warnings,
        storage_key=key,
    )
    db.add(row)
    await db.flush()
    refs: dict[str, SbomComponent] = {}
    for item in preview.components:
        reference = item.pop("ref")
        component = SbomComponent(sbom_id=row.id, **item)
        refs[reference] = component
        db.add(component)
    await db.flush()
    for dependency in preview.dependencies:
        source = refs.get(dependency["ref"])
        if not source:
            continue
        for target_ref in dependency["depends_on"]:
            target = refs.get(str(target_ref))
            if target:
                db.add(
                    SbomDependency(
                        sbom_id=row.id,
                        source_component_id=source.id,
                        target_component_id=target.id,
                    )
                )
    if release_id:
        release.sbom_id = row.id
    await write_audit(
        db,
        user,
        "sbom.imported",
        "sbom",
        row.id,
        metadata={"sha256": digest, "components": len(refs)},
    )
    await db.commit()
    await db.refresh(row)
    return row


@router.get("/sboms")
async def list_sboms(
    application_id: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    user: User = Depends(require_permission("sboms.read")),
    db: AsyncSession = Depends(get_db),
):
    where = [SoftwareBillOfMaterials.organization_id == user.organization_id]
    if application_id:
        where.append(SoftwareBillOfMaterials.application_id == application_id)
    return await _page(
        db,
        SoftwareBillOfMaterials,
        where,
        page,
        page_size,
        SoftwareBillOfMaterials.created_at.desc(),
    )


@router.get("/sboms/{sbom_id}")
async def get_sbom(
    sbom_id: str,
    user: User = Depends(require_permission("sboms.read")),
    db: AsyncSession = Depends(get_db),
):
    return await _tenant_row(db, SoftwareBillOfMaterials, sbom_id, user.organization_id)


@router.post("/sboms/{sbom_id}/validate")
async def validate_sbom(
    sbom_id: str,
    user: User = Depends(require_permission("sboms.import")),
    db: AsyncSession = Depends(get_db),
):
    row = await _tenant_row(db, SoftwareBillOfMaterials, sbom_id, user.organization_id)
    row.validated = row.component_count > 0 and not row.validation_errors
    await write_audit(db, user, "sbom.validated", "sbom", row.id)
    await db.commit()
    return {"id": row.id, "validated": row.validated, "errors": row.validation_errors}


@router.get("/sboms/{sbom_id}/components")
async def sbom_components(
    sbom_id: str,
    user: User = Depends(require_permission("sboms.read")),
    db: AsyncSession = Depends(get_db),
):
    await _tenant_row(db, SoftwareBillOfMaterials, sbom_id, user.organization_id)
    return list(
        (
            await db.scalars(
                select(SbomComponent)
                .where(SbomComponent.sbom_id == sbom_id)
                .order_by(SbomComponent.name)
            )
        ).all()
    )


@router.get("/sboms/{sbom_id}/dependencies")
async def sbom_dependencies(
    sbom_id: str,
    user: User = Depends(require_permission("sboms.read")),
    db: AsyncSession = Depends(get_db),
):
    await _tenant_row(db, SoftwareBillOfMaterials, sbom_id, user.organization_id)
    return list(
        (await db.scalars(select(SbomDependency).where(SbomDependency.sbom_id == sbom_id))).all()
    )


@router.get("/sboms/{sbom_id}/vulnerabilities")
async def sbom_vulnerabilities(
    sbom_id: str,
    user: User = Depends(require_permission("sboms.read")),
    db: AsyncSession = Depends(get_db),
):
    sbom = await _tenant_row(db, SoftwareBillOfMaterials, sbom_id, user.organization_id)
    rows = list(
        (
            await db.scalars(
                select(ComponentReachability).where(
                    ComponentReachability.organization_id == user.organization_id,
                    ComponentReachability.component_id.in_(
                        select(SbomComponent.id).where(SbomComponent.sbom_id == sbom.id)
                    ),
                )
            )
        ).all()
    )
    return {"items": rows, "source": "local_vulnerability_intelligence"}


@router.get("/security-gates")
async def list_security_gates(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    user: User = Depends(require_permission("security_gates.read")),
    db: AsyncSession = Depends(get_db),
):
    return await _page(
        db,
        SecurityGatePolicy,
        [SecurityGatePolicy.organization_id == user.organization_id],
        page,
        page_size,
        SecurityGatePolicy.name,
    )


@router.post("/security-gates", status_code=201)
async def create_security_gate(
    payload: GatePayload,
    user: User = Depends(require_permission("security_gates.manage")),
    db: AsyncSession = Depends(get_db),
):
    row = SecurityGatePolicy(organization_id=user.organization_id, **payload.model_dump())
    db.add(row)
    await write_audit(db, user, "security_gate.created", "security_gate", row.id)
    await db.commit()
    await db.refresh(row)
    return row


@router.get("/security-gates/{gate_id}")
async def get_security_gate(
    gate_id: str,
    user: User = Depends(require_permission("security_gates.read")),
    db: AsyncSession = Depends(get_db),
):
    return await _tenant_row(db, SecurityGatePolicy, gate_id, user.organization_id)


@router.patch("/security-gates/{gate_id}")
async def patch_security_gate(
    gate_id: str,
    payload: GatePayload,
    user: User = Depends(require_permission("security_gates.manage")),
    db: AsyncSession = Depends(get_db),
):
    row = await _tenant_row(db, SecurityGatePolicy, gate_id, user.organization_id)
    for key, value in payload.model_dump().items():
        setattr(row, key, value)
    await write_audit(db, user, "security_gate.updated", "security_gate", row.id)
    await db.commit()
    await db.refresh(row)
    return row


@router.post("/security-gates/{gate_id}/evaluate")
async def evaluate_gate(
    gate_id: str,
    payload: GateEvaluationPayload,
    user: User = Depends(require_permission("security_gates.evaluate")),
    db: AsyncSession = Depends(get_db),
):
    gate = await _tenant_row(db, SecurityGatePolicy, gate_id, user.organization_id)
    app = await _application(db, payload.application_id, user.organization_id)
    release = None
    if payload.release_id:
        release = await _tenant_row(db, SoftwareRelease, payload.release_id, user.organization_id)
        if release.application_id != app.id:
            raise HTTPException(422, "Release belongs to another application")
    severity_rows = (
        await db.execute(
            select(Finding.technical_severity, func.count(Finding.id))
            .where(
                Finding.organization_id == user.organization_id,
                Finding.application_id == app.id,
                Finding.status.in_(["open", "confirmed"]),
            )
            .group_by(Finding.technical_severity)
        )
    ).all()
    severity = {str(getattr(level, "value", level)): count for level, count in severity_rows}
    sbom_present = bool(
        await db.scalar(
            select(SoftwareBillOfMaterials.id).where(
                SoftwareBillOfMaterials.organization_id == user.organization_id,
                SoftwareBillOfMaterials.application_id == app.id,
                SoftwareBillOfMaterials.validated.is_(True),
            )
        )
    )
    confirmed_secrets = (
        await db.scalar(
            select(func.count())
            .select_from(SecretObservation)
            .where(
                SecretObservation.organization_id == user.organization_id,
                SecretObservation.application_id == app.id,
                SecretObservation.status == "confirmed",
            )
        )
        or 0
    )
    result, reasons = evaluate_security_gate(
        policy={
            "minimum_appsec_score": gate.minimum_appsec_score,
            "maximum_critical_findings": gate.maximum_critical_findings,
            "maximum_high_findings": gate.maximum_high_findings,
            "block_confirmed_secrets": gate.block_confirmed_secrets,
            "block_unsigned_artifacts": gate.block_unsigned_artifacts,
            "require_sbom": gate.require_sbom,
        },
        state={
            "appsec_score": app.appsec_score,
            "critical_findings": severity.get("critical", 0),
            "high_findings": severity.get("high", 0),
            "confirmed_secrets": confirmed_secrets,
            "artifact_signed": bool(release and release.signature_verified),
            "has_sbom": sbom_present,
            "has_sca": sbom_present,
            "has_sast": False,
            "has_iac_scan": False,
            "has_container_scan": False,
        },
    )
    evaluation = SecurityGateEvaluation(
        organization_id=user.organization_id,
        policy_id=gate.id,
        application_id=app.id,
        release_id=release.id if release else None,
        result=result,
        reasons=reasons,
        expires_at=utcnow() + timedelta(hours=24),
    )
    db.add(evaluation)
    await write_audit(
        db,
        user,
        "security_gate.evaluated",
        "security_gate_evaluation",
        evaluation.id,
        metadata={"result": result},
    )
    await db.commit()
    await db.refresh(evaluation)
    return evaluation


@router.get("/security-gates/{gate_id}/evaluations")
async def gate_evaluations(
    gate_id: str,
    user: User = Depends(require_permission("security_gates.read")),
    db: AsyncSession = Depends(get_db),
):
    await _tenant_row(db, SecurityGatePolicy, gate_id, user.organization_id)
    return list(
        (
            await db.scalars(
                select(SecurityGateEvaluation)
                .where(
                    SecurityGateEvaluation.organization_id == user.organization_id,
                    SecurityGateEvaluation.policy_id == gate_id,
                )
                .order_by(SecurityGateEvaluation.evaluated_at.desc())
            )
        ).all()
    )


@router.get("/appsec-exceptions")
async def list_exceptions(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    user: User = Depends(require_permission("appsec_exceptions.read")),
    db: AsyncSession = Depends(get_db),
):
    return await _page(
        db,
        AppSecException,
        [AppSecException.organization_id == user.organization_id],
        page,
        page_size,
        AppSecException.created_at.desc(),
    )


@router.post("/appsec-exceptions", status_code=201)
async def request_exception(
    payload: ExceptionPayload,
    user: User = Depends(require_permission("appsec_exceptions.request")),
    db: AsyncSession = Depends(get_db),
):
    await _application(db, payload.application_id, user.organization_id)
    if payload.finding_id:
        await _tenant_row(db, Finding, payload.finding_id, user.organization_id)
    if payload.release_id:
        await _tenant_row(db, SoftwareRelease, payload.release_id, user.organization_id)
    now = utcnow()
    if payload.expires_at <= now or payload.review_date > payload.expires_at:
        raise HTTPException(422, "Invalid exception validity window")
    row = AppSecException(
        organization_id=user.organization_id,
        requested_by=user.id,
        status="pending",
        **payload.model_dump(),
    )
    db.add(row)
    await write_audit(db, user, "appsec_exception.requested", "appsec_exception", row.id)
    await db.commit()
    await db.refresh(row)
    return row


@router.get("/appsec-exceptions/{exception_id}")
async def get_exception(
    exception_id: str,
    user: User = Depends(require_permission("appsec_exceptions.read")),
    db: AsyncSession = Depends(get_db),
):
    return await _tenant_row(db, AppSecException, exception_id, user.organization_id)


async def _review_exception(
    db: AsyncSession,
    user: User,
    exception_id: str,
    status: Literal["approved", "rejected"],
    notes: str,
) -> AppSecException:
    row = await _tenant_row(db, AppSecException, exception_id, user.organization_id)
    if row.status != "pending":
        raise HTTPException(409, "Exception is not pending")
    if row.expires_at <= utcnow():
        row.status = "expired"
        await db.commit()
        raise HTTPException(409, "Exception has expired")
    row.status = status
    row.approved_by = user.id if status == "approved" else None
    await write_audit(
        db,
        user,
        f"appsec_exception.{status}",
        "appsec_exception",
        row.id,
        metadata={"review_notes": notes},
    )
    await db.commit()
    await db.refresh(row)
    return row


@router.post("/appsec-exceptions/{exception_id}/approve")
async def approve_exception(
    exception_id: str,
    payload: ReviewPayload,
    user: User = Depends(require_permission("appsec_exceptions.review")),
    db: AsyncSession = Depends(get_db),
):
    return await _review_exception(db, user, exception_id, "approved", payload.notes)


@router.post("/appsec-exceptions/{exception_id}/reject")
async def reject_exception(
    exception_id: str,
    payload: ReviewPayload,
    user: User = Depends(require_permission("appsec_exceptions.review")),
    db: AsyncSession = Depends(get_db),
):
    return await _review_exception(db, user, exception_id, "rejected", payload.notes)


@router.post("/appsec-exceptions/{exception_id}/revoke")
async def revoke_exception(
    exception_id: str,
    payload: ReviewPayload,
    user: User = Depends(require_permission("appsec_exceptions.review")),
    db: AsyncSession = Depends(get_db),
):
    row = await _tenant_row(db, AppSecException, exception_id, user.organization_id)
    if row.status not in {"pending", "approved"}:
        raise HTTPException(409, "Exception cannot be revoked")
    row.status = "revoked"
    await write_audit(
        db,
        user,
        "appsec_exception.revoked",
        "appsec_exception",
        row.id,
        metadata={"review_notes": payload.notes},
    )
    await db.commit()
    await db.refresh(row)
    return row


@router.get("/appsec-remediations")
async def list_remediations(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    user: User = Depends(require_permission("appsec_remediations.read")),
    db: AsyncSession = Depends(get_db),
):
    return await _page(
        db,
        AppSecRemediation,
        [AppSecRemediation.organization_id == user.organization_id],
        page,
        page_size,
        AppSecRemediation.created_at.desc(),
    )


@router.post("/appsec-remediations", status_code=201)
async def create_remediation(
    payload: RemediationPayload,
    user: User = Depends(require_permission("appsec_remediations.manage")),
    db: AsyncSession = Depends(get_db),
):
    finding = await _tenant_row(db, Finding, payload.finding_id, user.organization_id)
    await _application(db, payload.application_id, user.organization_id)
    if finding.application_id and finding.application_id != payload.application_id:
        raise HTTPException(422, "Finding belongs to another application")
    if payload.repository_id:
        await _tenant_row(db, CodeRepository, payload.repository_id, user.organization_id)
    row = AppSecRemediation(organization_id=user.organization_id, **payload.model_dump())
    db.add(row)
    await write_audit(db, user, "appsec_remediation.created", "appsec_remediation", row.id)
    await db.commit()
    await db.refresh(row)
    return row


@router.get("/appsec-remediations/{remediation_id}")
async def get_remediation(
    remediation_id: str,
    user: User = Depends(require_permission("appsec_remediations.read")),
    db: AsyncSession = Depends(get_db),
):
    return await _tenant_row(db, AppSecRemediation, remediation_id, user.organization_id)


@router.patch("/appsec-remediations/{remediation_id}")
async def patch_remediation(
    remediation_id: str,
    payload: RemediationPayload,
    user: User = Depends(require_permission("appsec_remediations.manage")),
    db: AsyncSession = Depends(get_db),
):
    row = await _tenant_row(db, AppSecRemediation, remediation_id, user.organization_id)
    for key, value in payload.model_dump().items():
        setattr(row, key, value)
    await write_audit(db, user, "appsec_remediation.updated", "appsec_remediation", row.id)
    await db.commit()
    await db.refresh(row)
    return row


@router.post("/appsec-remediations/{remediation_id}/request-retest")
async def request_remediation_retest(
    remediation_id: str,
    user: User = Depends(require_permission("appsec_remediations.manage")),
    db: AsyncSession = Depends(get_db),
):
    row = await _tenant_row(db, AppSecRemediation, remediation_id, user.organization_id)
    if row.status not in {"in_progress", "ready_for_validation", "completed"}:
        raise HTTPException(409, "Remediation is not ready for retest")
    row.status = "retest_requested"
    await write_audit(
        db,
        user,
        "appsec_remediation.retest_requested",
        "appsec_remediation",
        row.id,
    )
    await db.commit()
    return {"id": row.id, "status": row.status}


@router.get("/appsec/risk")
async def appsec_risk(
    user: User = Depends(require_permission("appsec_risk.read")),
    db: AsyncSession = Depends(get_db),
):
    rows = list(
        (
            await db.scalars(
                select(ApplicationAsset)
                .where(ApplicationAsset.organization_id == user.organization_id)
                .order_by(ApplicationAsset.risk_score.desc())
            )
        ).all()
    )
    return {
        "items": [
            {
                "application_id": row.id,
                "name": row.name,
                "risk_score": row.risk_score,
                "appsec_score": row.appsec_score,
                "exposure_score": row.exposure_score,
                "confidence": row.confidence,
            }
            for row in rows
        ],
        "formula_version": "appsec-risk-1.0",
    }


@router.get("/appsec/scores")
async def appsec_scores(
    user: User = Depends(require_permission("appsec_risk.read")),
    db: AsyncSession = Depends(get_db),
):
    return list(
        (
            await db.scalars(
                select(AppSecScore)
                .where(AppSecScore.organization_id == user.organization_id)
                .order_by(AppSecScore.calculated_at.desc())
            )
        ).all()
    )


@router.get("/appsec/command-center")
async def appsec_command_center(
    user: User = Depends(require_permission("appsec_risk.read")),
    db: AsyncSession = Depends(get_db),
):
    async def count(model: Any, *conditions: Any) -> int:
        return (
            await db.scalar(
                select(func.count())
                .select_from(model)
                .where(model.organization_id == user.organization_id, *conditions)
            )
            or 0
        )

    return {
        "applications": await count(ApplicationAsset),
        "internet_exposed": await count(
            ApplicationAsset, ApplicationAsset.internet_exposed.is_(True)
        ),
        "apis": await count(ApiAsset),
        "repositories": await count(CodeRepository),
        "releases": await count(SoftwareRelease),
        "validated_sboms": await count(
            SoftwareBillOfMaterials, SoftwareBillOfMaterials.validated.is_(True)
        ),
        "confirmed_secrets": await count(
            SecretObservation, SecretObservation.status == "confirmed"
        ),
        "open_exceptions": await count(AppSecException, AppSecException.status == "pending"),
        "open_remediations": await count(
            AppSecRemediation, AppSecRemediation.status != "completed"
        ),
        "generated_at": utcnow(),
    }


@router.get("/appsec/coverage")
async def appsec_coverage(
    user: User = Depends(require_permission("appsec_risk.read")),
    db: AsyncSession = Depends(get_db),
):
    apps = (
        await db.scalar(
            select(func.count())
            .select_from(ApplicationAsset)
            .where(ApplicationAsset.organization_id == user.organization_id)
        )
        or 0
    )
    assessed = (
        await db.scalar(
            select(func.count())
            .select_from(ApplicationAsset)
            .where(
                ApplicationAsset.organization_id == user.organization_id,
                ApplicationAsset.last_assessed_at.is_not(None),
            )
        )
        or 0
    )
    return {
        "applications": apps,
        "assessed": assessed,
        "coverage_percentage": round((assessed / apps * 100) if apps else 0, 2),
    }


@router.get("/appsec/trends")
async def appsec_trends(
    user: User = Depends(require_permission("appsec_risk.read")),
    db: AsyncSession = Depends(get_db),
):
    rows = list(
        (
            await db.scalars(
                select(AppSecScore)
                .where(AppSecScore.organization_id == user.organization_id)
                .order_by(AppSecScore.calculated_at.desc())
                .limit(90)
            )
        ).all()
    )
    return {"items": rows, "window_days": 90}
