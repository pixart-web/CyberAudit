import hashlib
import uuid
from contextlib import asynccontextmanager
from datetime import date, datetime, timedelta, timezone
from typing import Any

from fastapi import Depends, FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from sqlalchemy import func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.responses import Response

from cyberaudit.audit import write_audit
from cyberaudit.config import get_settings
from cyberaudit.db import Base, engine, get_db
from cyberaudit.execution_api import router as execution_router
from cyberaudit.models import (
    Asset,
    AuditLog,
    AuthorizationDocument,
    Client,
    Engagement,
    EngagementMode,
    EngagementStatus,
    Evidence,
    Finding,
    Organization,
    RefreshToken,
    Retest,
    RetestStatus,
    Role,
    ScanJob,
    Scope,
    ScopeTarget,
    ToolAdapterDefinition,
    User,
    utcnow,
)
from cyberaudit.phase3_api import router as phase3_router
from cyberaudit.phase4_api import router as phase4_router
from cyberaudit.phase5_api import router as phase5_router
from cyberaudit.policy import ScopePolicyEngine, normalized_target
from cyberaudit.schemas import (
    AssetCreate,
    AssetRead,
    ClientCreate,
    ClientRead,
    EngagementCreate,
    EngagementRead,
    LoginRequest,
    OrganizationCreate,
    OrganizationRead,
    Page,
    PolicyRequest,
    PolicyResponse,
    ScopeCreate,
    ScopeRead,
    StateChange,
    TargetCreate,
    TargetRead,
    TokenResponse,
    UserCreate,
    UserRead,
)
from cyberaudit.security import (
    create_access_token,
    current_user,
    hash_password,
    issue_refresh_token,
    require_permission,
    verify_password,
)
from cyberaudit.storage import LocalStorage

settings = get_settings()
policy_engine = ScopePolicyEngine()
storage = LocalStorage()


@asynccontextmanager
async def lifespan(_: FastAPI):
    if settings.environment == "development" and settings.database_url.startswith("sqlite"):
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
    yield


app = FastAPI(title="CyberAudit API", version="1.0.0", lifespan=lifespan)
app.include_router(execution_router)
app.include_router(phase3_router)
app.include_router(phase4_router)
app.include_router(phase5_router)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.app_origin],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def error_response(
    request: Request, status_code: int, code: str, message: str, details: Any = None
):
    request_id = getattr(request.state, "request_id", str(uuid.uuid4()))
    return JSONResponse(
        status_code=status_code,
        content={
            "error": {
                "code": code,
                "message": message,
                "details": details or {},
                "request_id": request_id,
            }
        },
    )


@app.middleware("http")
async def request_context(request: Request, call_next):
    request.state.request_id = request.headers.get("x-request-id", str(uuid.uuid4()))
    response = await call_next(request)
    response.headers["x-request-id"] = request.state.request_id
    response.headers["x-content-type-options"] = "nosniff"
    response.headers["x-frame-options"] = "DENY"
    response.headers["referrer-policy"] = "no-referrer"
    return response


@app.exception_handler(HTTPException)
async def http_error(request: Request, exc: HTTPException):
    return error_response(request, exc.status_code, f"HTTP_{exc.status_code}", str(exc.detail))


@app.exception_handler(RequestValidationError)
async def validation_error(request: Request, exc: RequestValidationError):
    return error_response(request, 422, "VALIDATION_ERROR", "Invalid request", exc.errors())


@app.get("/health", tags=["system"])
async def health():
    return {"status": "ok", "service": "cyberaudit-api"}


@app.get("/metrics", include_in_schema=False)
async def metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.post("/api/v1/auth/login", response_model=TokenResponse, tags=["auth"])
async def login(payload: LoginRequest, db: AsyncSession = Depends(get_db)):
    user = await db.scalar(select(User).where(func.lower(User.email) == payload.email.lower()))
    now = datetime.now(timezone.utc)
    if not user:
        raise HTTPException(401, "Invalid credentials")
    if user.locked_until and user.locked_until > now:
        raise HTTPException(423, "Account temporarily locked")
    if not verify_password(payload.password, user.password_hash):
        user.failed_login_attempts += 1
        if user.failed_login_attempts >= 5:
            user.locked_until = now + timedelta(minutes=15)
            user.failed_login_attempts = 0
        await write_audit(db, user, "auth.login_failed", "user", user.id, "failure")
        await db.commit()
        raise HTTPException(401, "Invalid credentials")
    user.failed_login_attempts = 0
    user.locked_until = None
    user.last_login_at = now
    refresh = await issue_refresh_token(db, user)
    await write_audit(db, user, "auth.login", "user", user.id)
    await db.commit()
    return TokenResponse(
        access_token=create_access_token(user),
        refresh_token=refresh,
        expires_in=settings.access_token_minutes * 60,
    )


@app.post("/api/v1/auth/refresh", response_model=TokenResponse, tags=["auth"])
async def refresh(refresh_token: str, db: AsyncSession = Depends(get_db)):
    try:
        token_id, raw = refresh_token.split(".", 1)
    except ValueError as exc:
        raise HTTPException(401, "Invalid refresh token") from exc
    stored = await db.get(RefreshToken, token_id)
    digest = hashlib.sha256(raw.encode()).hexdigest()
    now = datetime.now(timezone.utc)
    if not stored or stored.token_hash != digest or stored.expires_at <= now:
        raise HTTPException(401, "Invalid refresh token")
    if stored.revoked_at:
        await db.execute(
            update(RefreshToken)
            .where(RefreshToken.family_id == stored.family_id)
            .values(revoked_at=now)
        )
        await db.commit()
        raise HTTPException(401, "Refresh token reuse detected")
    user = await db.get(User, stored.user_id)
    if not user or user.status != "active":
        raise HTTPException(401, "Inactive user")
    stored.revoked_at = now
    rotated = await issue_refresh_token(db, user, stored.family_id)
    stored.replaced_by = rotated.split(".", 1)[0]
    await db.commit()
    return TokenResponse(
        access_token=create_access_token(user),
        refresh_token=rotated,
        expires_in=settings.access_token_minutes * 60,
    )


@app.post("/api/v1/auth/logout", status_code=204, tags=["auth"])
async def logout(refresh_token: str, db: AsyncSession = Depends(get_db)):
    token_id = refresh_token.split(".", 1)[0]
    stored = await db.get(RefreshToken, token_id)
    if stored:
        stored.revoked_at = utcnow()
        await db.commit()


@app.get("/api/v1/auth/me", response_model=UserRead, tags=["auth"])
async def me(user: User = Depends(current_user)):
    return user


async def paginated(
    db: AsyncSession, model: Any, where: list[Any], page: int, page_size: int, order: Any
):
    total = await db.scalar(select(func.count()).select_from(model).where(*where))
    items = list(
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
    return {"items": items, "total": total or 0, "page": page, "page_size": page_size}


@app.get("/api/v1/organizations", response_model=Page[OrganizationRead], tags=["organizations"])
async def organizations(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    user: User = Depends(require_permission("organizations.read")),
    db: AsyncSession = Depends(get_db),
):
    return await paginated(
        db,
        Organization,
        [Organization.id == user.organization_id, Organization.deleted_at.is_(None)],
        page,
        page_size,
        Organization.name,
    )


@app.post("/api/v1/organizations", response_model=OrganizationRead, tags=["organizations"])
async def create_organization(
    payload: OrganizationCreate,
    user: User = Depends(require_permission("organizations.manage")),
    db: AsyncSession = Depends(get_db),
):
    organization = await db.get(Organization, user.organization_id)
    if not organization:
        raise HTTPException(404, "Organization not found")
    if payload.slug != organization.slug:
        raise HTTPException(403, "Cross-tenant organization creation is not allowed")
    return organization


@app.get("/api/v1/clients", response_model=Page[ClientRead], tags=["clients"])
async def clients(
    q: str = "",
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    user: User = Depends(require_permission("clients.read")),
    db: AsyncSession = Depends(get_db),
):
    where = [Client.organization_id == user.organization_id, Client.deleted_at.is_(None)]
    if q:
        where.append(or_(Client.name.ilike(f"%{q}%"), Client.legal_name.ilike(f"%{q}%")))
    return await paginated(db, Client, where, page, page_size, Client.name)


@app.post("/api/v1/clients", response_model=ClientRead, status_code=201, tags=["clients"])
async def create_client(
    payload: ClientCreate,
    user: User = Depends(require_permission("clients.manage")),
    db: AsyncSession = Depends(get_db),
):
    item = Client(organization_id=user.organization_id, **payload.model_dump())
    db.add(item)
    await db.flush()
    await write_audit(db, user, "client.created", "client", item.id)
    await db.commit()
    await db.refresh(item)
    return item


@app.delete("/api/v1/clients/{item_id}", status_code=204, tags=["clients"])
async def delete_client(
    item_id: str,
    user: User = Depends(require_permission("clients.manage")),
    db: AsyncSession = Depends(get_db),
):
    item = await db.scalar(
        select(Client).where(
            Client.id == item_id,
            Client.organization_id == user.organization_id,
            Client.deleted_at.is_(None),
        )
    )
    if not item:
        raise HTTPException(404, "Client not found")
    item.deleted_at = utcnow()
    await write_audit(db, user, "client.deleted", "client", item.id)
    await db.commit()


@app.get("/api/v1/engagements", response_model=Page[EngagementRead], tags=["engagements"])
async def engagements(
    q: str = "",
    status: EngagementStatus | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    user: User = Depends(require_permission("engagements.read")),
    db: AsyncSession = Depends(get_db),
):
    where = [Engagement.organization_id == user.organization_id, Engagement.deleted_at.is_(None)]
    if q:
        where.append(or_(Engagement.name.ilike(f"%{q}%"), Engagement.code.ilike(f"%{q}%")))
    if status:
        where.append(Engagement.status == status)
    return await paginated(db, Engagement, where, page, page_size, Engagement.created_at.desc())


@app.post(
    "/api/v1/engagements", response_model=EngagementRead, status_code=201, tags=["engagements"]
)
async def create_engagement(
    payload: EngagementCreate,
    user: User = Depends(require_permission("engagements.manage")),
    db: AsyncSession = Depends(get_db),
):
    client = await db.scalar(
        select(Client).where(
            Client.id == payload.client_id,
            Client.organization_id == user.organization_id,
            Client.deleted_at.is_(None),
        )
    )
    if not client:
        raise HTTPException(404, "Client not found")
    if payload.owner_id:
        owner = await db.scalar(
            select(User).where(
                User.id == payload.owner_id, User.organization_id == user.organization_id
            )
        )
        if not owner:
            raise HTTPException(422, "Owner must belong to the organization")
    item = Engagement(
        organization_id=user.organization_id, status=EngagementStatus.DRAFT, **payload.model_dump()
    )
    db.add(item)
    await db.flush()
    await write_audit(db, user, "engagement.created", "engagement", item.id)
    await db.commit()
    await db.refresh(item)
    return item


TRANSITIONS = {
    EngagementStatus.DRAFT: {EngagementStatus.PENDING_AUTHORIZATION, EngagementStatus.CANCELLED},
    EngagementStatus.PENDING_AUTHORIZATION: {
        EngagementStatus.AUTHORIZED,
        EngagementStatus.CANCELLED,
    },
    EngagementStatus.AUTHORIZED: {EngagementStatus.ACTIVE, EngagementStatus.CANCELLED},
    EngagementStatus.ACTIVE: {
        EngagementStatus.PAUSED,
        EngagementStatus.COMPLETED,
        EngagementStatus.CANCELLED,
    },
    EngagementStatus.PAUSED: {EngagementStatus.ACTIVE, EngagementStatus.CANCELLED},
    EngagementStatus.COMPLETED: set(),
    EngagementStatus.CANCELLED: set(),
}


@app.patch(
    "/api/v1/engagements/{item_id}/status", response_model=EngagementRead, tags=["engagements"]
)
async def change_engagement_status(
    item_id: str,
    payload: StateChange,
    user: User = Depends(require_permission("engagements.manage")),
    db: AsyncSession = Depends(get_db),
):
    item = await db.scalar(
        select(Engagement).where(
            Engagement.id == item_id,
            Engagement.organization_id == user.organization_id,
            Engagement.deleted_at.is_(None),
        )
    )
    if not item:
        raise HTTPException(404, "Engagement not found")
    if payload.status not in TRANSITIONS[item.status]:
        raise HTTPException(
            409, f"Invalid transition from {item.status.value} to {payload.status.value}"
        )
    if payload.status in {EngagementStatus.AUTHORIZED, EngagementStatus.ACTIVE}:
        today = date.today()
        auth = await db.scalar(
            select(AuthorizationDocument).where(
                AuthorizationDocument.engagement_id == item.id,
                AuthorizationDocument.organization_id == user.organization_id,
                AuthorizationDocument.status == "valid",
                AuthorizationDocument.valid_from <= today,
                AuthorizationDocument.valid_until >= today,
            )
        )
        scope = await db.scalar(
            select(Scope).where(
                Scope.engagement_id == item.id,
                Scope.organization_id == user.organization_id,
                Scope.status == "active",
                Scope.deleted_at.is_(None),
            )
        )
        target = (
            await db.scalar(
                select(ScopeTarget).where(
                    ScopeTarget.scope_id == scope.id, ScopeTarget.allowed.is_(True)
                )
            )
            if scope
            else None
        )
        if item.mode == EngagementMode.CLIENT and (
            not auth or not scope or not target or not item.owner_id
        ):
            raise HTTPException(
                409, "Valid authorization, active scope, allowed target and owner are required"
            )
    old = item.status.value
    item.status = payload.status
    await write_audit(
        db,
        user,
        "engagement.status_changed",
        "engagement",
        item.id,
        metadata={"from": old, "to": payload.status.value},
    )
    await db.commit()
    await db.refresh(item)
    return item


@app.get("/api/v1/scopes", response_model=Page[ScopeRead], tags=["scopes"])
async def scopes(
    engagement_id: str | None = None,
    page: int = 1,
    page_size: int = 20,
    user: User = Depends(require_permission("scopes.read")),
    db: AsyncSession = Depends(get_db),
):
    where = [Scope.organization_id == user.organization_id, Scope.deleted_at.is_(None)]
    if engagement_id:
        where.append(Scope.engagement_id == engagement_id)
    return await paginated(db, Scope, where, page, page_size, Scope.created_at.desc())


@app.post("/api/v1/scopes", response_model=ScopeRead, status_code=201, tags=["scopes"])
async def create_scope(
    payload: ScopeCreate,
    user: User = Depends(require_permission("scopes.manage")),
    db: AsyncSession = Depends(get_db),
):
    engagement = await db.scalar(
        select(Engagement).where(
            Engagement.id == payload.engagement_id,
            Engagement.organization_id == user.organization_id,
        )
    )
    if not engagement:
        raise HTTPException(404, "Engagement not found")
    item = Scope(organization_id=user.organization_id, **payload.model_dump())
    db.add(item)
    await db.flush()
    await write_audit(db, user, "scope.created", "scope", item.id)
    await db.commit()
    await db.refresh(item)
    return item


@app.get("/api/v1/scope-targets", response_model=Page[TargetRead], tags=["scope-targets"])
async def scope_targets(
    scope_id: str,
    page: int = 1,
    page_size: int = 20,
    user: User = Depends(require_permission("scopes.read")),
    db: AsyncSession = Depends(get_db),
):
    scope = await db.scalar(
        select(Scope).where(Scope.id == scope_id, Scope.organization_id == user.organization_id)
    )
    if not scope:
        raise HTTPException(404, "Scope not found")
    return await paginated(
        db,
        ScopeTarget,
        [ScopeTarget.scope_id == scope_id],
        page,
        page_size,
        ScopeTarget.created_at.desc(),
    )


@app.post(
    "/api/v1/scope-targets", response_model=TargetRead, status_code=201, tags=["scope-targets"]
)
async def create_target(
    payload: TargetCreate,
    user: User = Depends(require_permission("scopes.manage")),
    db: AsyncSession = Depends(get_db),
):
    scope = await db.scalar(
        select(Scope).where(
            Scope.id == payload.scope_id, Scope.organization_id == user.organization_id
        )
    )
    if not scope:
        raise HTTPException(404, "Scope not found")
    try:
        normalized = normalized_target(payload.target_type, payload.target_value)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    item = ScopeTarget(**payload.model_dump(), normalized_value=normalized)
    db.add(item)
    await db.flush()
    await write_audit(db, user, "scope_target.created", "scope_target", item.id)
    await db.commit()
    await db.refresh(item)
    return item


@app.get("/api/v1/assets", response_model=Page[AssetRead], tags=["assets"])
async def assets(
    q: str = "",
    page: int = 1,
    page_size: int = 20,
    user: User = Depends(require_permission("assets.read")),
    db: AsyncSession = Depends(get_db),
):
    where = [Asset.organization_id == user.organization_id, Asset.deleted_at.is_(None)]
    if q:
        where.append(or_(Asset.name.ilike(f"%{q}%"), Asset.identifier.ilike(f"%{q}%")))
    return await paginated(db, Asset, where, page, page_size, Asset.created_at.desc())


@app.post("/api/v1/assets", response_model=AssetRead, status_code=201, tags=["assets"])
async def create_asset(
    payload: AssetCreate,
    user: User = Depends(require_permission("assets.manage")),
    db: AsyncSession = Depends(get_db),
):
    engagement = await db.scalar(
        select(Engagement).where(
            Engagement.id == payload.engagement_id,
            Engagement.organization_id == user.organization_id,
        )
    )
    if not engagement:
        raise HTTPException(404, "Engagement not found")
    item = Asset(organization_id=user.organization_id, **payload.model_dump())
    db.add(item)
    await db.flush()
    await write_audit(db, user, "asset.created", "asset", item.id)
    await db.commit()
    await db.refresh(item)
    return item


@app.get("/api/v1/users", response_model=Page[UserRead], tags=["users"])
async def users(
    q: str = "",
    page: int = 1,
    page_size: int = 20,
    user: User = Depends(require_permission("users.manage")),
    db: AsyncSession = Depends(get_db),
):
    where = [User.organization_id == user.organization_id, User.deleted_at.is_(None)]
    if q:
        where.append(or_(User.name.ilike(f"%{q}%"), User.email.ilike(f"%{q}%")))
    return await paginated(db, User, where, page, page_size, User.name)


@app.post("/api/v1/users", response_model=UserRead, status_code=201, tags=["users"])
async def create_user(
    payload: UserCreate,
    user: User = Depends(require_permission("users.manage")),
    db: AsyncSession = Depends(get_db),
):
    role = await db.scalar(select(Role).where(Role.name == payload.role))
    if not role:
        raise HTTPException(422, "Unknown role")
    item = User(
        organization_id=user.organization_id,
        name=payload.name,
        email=payload.email.lower(),
        password_hash=hash_password(payload.password),
        roles=[role],
    )
    db.add(item)
    await db.flush()
    await write_audit(db, user, "user.created", "user", item.id)
    await db.commit()
    await db.refresh(item)
    return item


@app.post("/api/v1/authorizations", status_code=201, tags=["authorizations"])
async def upload_authorization(
    engagement_id: str = Form(),
    valid_from: date = Form(),
    valid_until: date = Form(),
    signed_by: str = Form(),
    file: UploadFile = File(),
    user: User = Depends(require_permission("authorizations.manage")),
    db: AsyncSession = Depends(get_db),
):
    engagement = await db.scalar(
        select(Engagement).where(
            Engagement.id == engagement_id, Engagement.organization_id == user.organization_id
        )
    )
    if not engagement:
        raise HTTPException(404, "Engagement not found")
    if valid_until < valid_from:
        raise HTTPException(422, "Invalid validity period")
    try:
        key, digest, size = await storage.save_pdf(file)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    item = AuthorizationDocument(
        organization_id=user.organization_id,
        engagement_id=engagement_id,
        filename=(file.filename or "authorization.pdf")[:255],
        storage_key=key,
        file_hash=digest,
        valid_from=valid_from,
        valid_until=valid_until,
        signed_by=signed_by,
        uploaded_by=user.id,
    )
    db.add(item)
    await db.flush()
    await write_audit(
        db,
        user,
        "authorization.uploaded",
        "authorization",
        item.id,
        metadata={"sha256": digest, "size": size},
    )
    await db.commit()
    return {
        "id": item.id,
        "filename": item.filename,
        "file_hash": item.file_hash,
        "status": item.status,
    }


@app.post("/api/v1/policy/evaluate", response_model=PolicyResponse, tags=["policy"])
async def evaluate_policy(
    payload: PolicyRequest,
    user: User = Depends(require_permission("jobs.execute")),
    db: AsyncSession = Depends(get_db),
):
    if payload.organization_id != user.organization_id or payload.operator_id != user.id:
        await write_audit(
            db,
            user,
            "policy.evaluated",
            "engagement",
            payload.engagement_id,
            "denied",
            {"reason": "caller_context_mismatch"},
        )
        await db.commit()
        raise HTTPException(403, "Policy context must match the authenticated user")
    result = await policy_engine.evaluate(db, payload)
    await write_audit(
        db,
        user,
        "policy.evaluated",
        "engagement",
        payload.engagement_id,
        result.decision,
        {"reasons": result.reasons, "policy_version": result.policy_version},
    )
    await db.commit()
    return result


@app.get("/api/v1/audit-logs", tags=["audit-logs"])
async def audit_logs(
    page: int = 1,
    page_size: int = 50,
    user: User = Depends(require_permission("audit_logs.read")),
    db: AsyncSession = Depends(get_db),
):
    return await paginated(
        db,
        AuditLog,
        [AuditLog.organization_id == user.organization_id],
        page,
        page_size,
        AuditLog.created_at.desc(),
    )


@app.get("/api/v1/dashboard", tags=["dashboard"])
async def dashboard(
    user: User = Depends(require_permission("engagements.read")), db: AsyncSession = Depends(get_db)
):
    assets_count = await db.scalar(
        select(func.count())
        .select_from(Asset)
        .where(Asset.organization_id == user.organization_id, Asset.deleted_at.is_(None))
    )
    active_count = await db.scalar(
        select(func.count())
        .select_from(Engagement)
        .where(
            Engagement.organization_id == user.organization_id,
            Engagement.status == EngagementStatus.ACTIVE,
        )
    )
    active = list(
        (
            await db.scalars(
                select(Engagement)
                .where(
                    Engagement.organization_id == user.organization_id,
                    Engagement.status.in_(
                        [EngagementStatus.ACTIVE, EngagementStatus.PENDING_AUTHORIZATION]
                    ),
                )
                .limit(5)
            )
        ).all()
    )
    logs = list(
        (
            await db.scalars(
                select(AuditLog)
                .where(AuditLog.organization_id == user.organization_id)
                .order_by(AuditLog.created_at.desc())
                .limit(6)
            )
        ).all()
    )
    jobs_running = await db.scalar(
        select(func.count())
        .select_from(ScanJob)
        .where(
            ScanJob.organization_id == user.organization_id,
            ScanJob.status.in_(["QUEUED", "STARTING", "RUNNING", "PROCESSING_RESULTS"]),
        )
    )
    jobs_failed = await db.scalar(
        select(func.count())
        .select_from(ScanJob)
        .where(
            ScanJob.organization_id == user.organization_id,
            ScanJob.status.in_(["FAILED", "TIMED_OUT"]),
        )
    )
    jobs_completed = await db.scalar(
        select(func.count())
        .select_from(ScanJob)
        .where(
            ScanJob.organization_id == user.organization_id,
            ScanJob.status.in_(["COMPLETED", "COMPLETED_WITH_WARNINGS"]),
        )
    )
    jobs_total = await db.scalar(
        select(func.count())
        .select_from(ScanJob)
        .where(ScanJob.organization_id == user.organization_id)
    )
    adapters_online = await db.scalar(
        select(func.count())
        .select_from(ToolAdapterDefinition)
        .where(
            ToolAdapterDefinition.enabled.is_(True),
            ToolAdapterDefinition.health_status == "online",
        )
    )
    finding_counts = {
        severity: await db.scalar(
            select(func.count())
            .select_from(Finding)
            .where(
                Finding.organization_id == user.organization_id,
                Finding.technical_severity == severity,
            )
        )
        or 0
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    }
    findings_total = sum(finding_counts.values())
    evidence_count = await db.scalar(
        select(func.count())
        .select_from(Evidence)
        .where(Evidence.organization_id == user.organization_id)
    )
    retests_pending = await db.scalar(
        select(func.count())
        .select_from(Retest)
        .where(
            Retest.organization_id == user.organization_id,
            Retest.status.in_([RetestStatus.REQUESTED, RetestStatus.QUEUED, RetestStatus.RUNNING]),
        )
    )
    return {
        "metrics": {
            "posture": 78,
            "assets": assets_count or 0,
            "findings": findings_total,
            "active_engagements": active_count or 0,
            "retest_rate": 84,
        },
        "severity": [
            {"name": "Crítica", "value": finding_counts["CRITICAL"], "color": "#FF404D"},
            {"name": "Alta", "value": finding_counts["HIGH"], "color": "#FF851B"},
            {"name": "Média", "value": finding_counts["MEDIUM"], "color": "#F4CA24"},
            {"name": "Baixa", "value": finding_counts["LOW"], "color": "#20D9FF"},
        ],
        "top_risks": [
            {"title": "Autenticação sem MFA", "severity": "critical", "asset": "Identity Gateway"},
            {"title": "TLS desatualizado", "severity": "high", "asset": "api.internal"},
            {"title": "Privilégios excessivos", "severity": "high", "asset": "Cloud Account"},
            {"title": "Headers incompletos", "severity": "medium", "asset": "Web Portal"},
            {"title": "Inventário divergente", "severity": "medium", "asset": "Network"},
        ],
        "engagements": [
            {
                "id": item.id,
                "name": item.name,
                "code": item.code,
                "status": item.status.value,
                "risk": item.risk_level.value,
            }
            for item in active
        ],
        "activity": [
            {
                "action": log.action,
                "resource_type": log.resource_type,
                "result": log.result,
                "created_at": log.created_at.isoformat(),
            }
            for log in logs
        ],
        "jobs": [
            {
                "name": "Jobs em execução",
                "when": f"{jobs_running or 0} ativos",
                "status": "running",
            },
            {
                "name": "Jobs falhados",
                "when": f"{jobs_failed or 0} requerem atenção",
                "status": "failed" if jobs_failed else "healthy",
            },
        ],
        "incidents": [
            {"time": "09:14", "title": "Tentativa de acesso bloqueada", "tone": "danger"},
            {"time": "11:42", "title": "Âmbito atualizado", "tone": "info"},
            {"time": "14:20", "title": "Autorização validada", "tone": "success"},
        ],
        "adapters": [
            {"name": "PostgreSQL", "status": "online"},
            {"name": "Redis", "status": "online"},
            {"name": "Local Storage", "status": "online"},
            {"name": "Adaptadores", "status": "online" if adapters_online else "disabled"},
        ],
        "execution_metrics": {
            "running": jobs_running or 0,
            "failed": jobs_failed or 0,
            "completed": jobs_completed or 0,
            "adapters_online": adapters_online or 0,
            "completion_rate": round((jobs_completed or 0) * 100 / (jobs_total or 1)),
            "evidence": evidence_count or 0,
            "retests_pending": retests_pending or 0,
        },
    }
