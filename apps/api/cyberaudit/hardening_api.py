"""Operational hardening APIs. Sensitive values are never serialized."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal, cast
from uuid import uuid4

from botocore.exceptions import BotoCoreError
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, inspect, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from cyberaudit.audit import write_audit
from cyberaudit.config import get_settings
from cyberaudit.db import get_db
from cyberaudit.dead_letter import DeadLetterService
from cyberaudit.enterprise_auth import (
    OidcClient,
    OidcStateStore,
    SessionService,
    generate_recovery_codes,
    verify_totp,
)
from cyberaudit.hardening_models import (
    AuthenticationProvider,
    BackupRecord,
    DeadLetterMessage,
    ExternalGroupRoleMapping,
    FeatureFlag,
    LicenseRecord,
    MfaFactor,
    RecoveryCode,
    RestoreRecord,
    ServiceLevelObjective,
    TelemetryPreference,
    UserSession,
)
from cyberaudit.models import Organization, Role, User
from cyberaudit.object_storage import object_storage_provider
from cyberaudit.observability import (
    dead_letter_replays_total,
    production_readiness_blockers,
    webauthn_authentication_total,
    webauthn_registration_total,
)
from cyberaudit.product_services import EDITIONS, LicenseService, telemetry_preview
from cyberaudit.readiness import ProductionReadinessGate
from cyberaudit.rls import set_tenant_context
from cyberaudit.secrets import SecretReference, secret_provider
from cyberaudit.security import (
    create_access_token,
    create_step_up_token,
    decode_token,
    issue_refresh_token,
    require_permission,
)
from cyberaudit.webauthn_service import WebAuthnService

router = APIRouter(prefix="/api/v1", tags=["product-hardening"])


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class OidcStart(StrictModel):
    organization_slug: str = Field(pattern=r"^[a-z0-9-]{2,80}$")
    code_challenge: str = Field(min_length=43, max_length=128)
    verifier_hash: str = Field(pattern=r"^[a-f0-9]{64}$")


class OidcCallback(StrictModel):
    organization_slug: str = Field(pattern=r"^[a-z0-9-]{2,80}$")
    code: str = Field(min_length=4, max_length=4096)
    state: str = Field(min_length=32, max_length=256)
    code_verifier: str = Field(min_length=43, max_length=128)


class TelemetryUpdate(StrictModel):
    enabled: bool
    allowed_categories: list[str] = Field(default_factory=list, max_length=20)


class FeatureFlagPayload(StrictModel):
    code: str = Field(pattern=r"^[a-z0-9_.-]{2,120}$")
    description: str = Field(default="", max_length=500)
    enabled: bool = False
    edition: str | None = None
    configuration: dict[str, Any] = Field(default_factory=dict)


class TotpEnrollment(StrictModel):
    label: str = Field(min_length=2, max_length=120)
    secret_reference: str = Field(min_length=8, max_length=500)
    code: str = Field(pattern=r"^\d{6}$")


class RecoveryCodeRequest(StrictModel):
    count: int = Field(default=10, ge=5, le=20)


class WebAuthnRegistrationFinish(StrictModel):
    challenge_id: str = Field(min_length=24, max_length=128)
    label: str = Field(min_length=2, max_length=120)
    credential: dict[str, Any]


class WebAuthnAuthenticationFinish(StrictModel):
    challenge_id: str = Field(min_length=24, max_length=128)
    credential: dict[str, Any]


class WebAuthnRevoke(StrictModel):
    step_up_token: str = Field(min_length=32, max_length=4096)


class DeadLetterAction(StrictModel):
    step_up_token: str | None = Field(default=None, min_length=32, max_length=4096)


def serialize(record: Any) -> dict[str, Any]:
    hidden = {
        "session_token_hash",
        "csrf_token_hash",
        "client_secret_reference",
        "signed_payload",
    }
    return {
        column.key: getattr(record, column.key)
        for column in inspect(record).mapper.column_attrs
        if column.key not in hidden
    }


async def _active_organization_by_slug(
    db: AsyncSession, organization_slug: str
) -> Organization | None:
    if db.get_bind().dialect.name == "postgresql":
        organization_id = await db.scalar(
            text("SELECT cyberaudit_resolve_active_organization(:slug)"),
            {"slug": organization_slug},
        )
        if not organization_id:
            return None
        await set_tenant_context(db, str(organization_id))
        return await db.get(Organization, str(organization_id))
    organization = await db.scalar(
        select(Organization).where(
            Organization.slug == organization_slug,
            Organization.status == "active",
        )
    )
    if organization:
        await set_tenant_context(db, organization.id)
    return organization


@router.post("/auth/oidc/start")
async def oidc_start(payload: OidcStart, db: AsyncSession = Depends(get_db)):
    settings = get_settings()
    organization = await _active_organization_by_slug(db, payload.organization_slug)
    if not organization:
        raise HTTPException(404, "Authentication provider unavailable")
    transaction = await OidcStateStore(settings.redis_url).create(
        organization.id, payload.verifier_hash
    )
    url = await OidcClient(settings).authorization_url(transaction, payload.code_challenge)
    return {"authorization_url": url, "state": transaction.state, "expires_in": 600}


@router.post("/auth/oidc/callback")
async def oidc_callback(
    payload: OidcCallback, response: Response, db: AsyncSession = Depends(get_db)
):
    settings = get_settings()
    organization = await _active_organization_by_slug(db, payload.organization_slug)
    if not organization:
        raise HTTPException(401, "Authentication failed")
    provider_record = await db.scalar(
        select(AuthenticationProvider).where(
            AuthenticationProvider.organization_id == organization.id,
            AuthenticationProvider.enabled.is_(True),
            AuthenticationProvider.issuer == settings.oidc_issuer,
        )
    )
    if settings.production_like and not provider_record:
        raise HTTPException(401, "Authentication provider unavailable")
    try:
        transaction = await OidcStateStore(settings.redis_url).consume(
            organization.id, payload.state
        )
    except (ValueError, OSError) as exc:
        raise HTTPException(401, "Authentication transaction is invalid") from exc
    resolved_secret: str | None = None
    if settings.oidc_client_secret_reference:
        resolved_secret = await secret_provider(settings).resolve_reference(
            SecretReference(settings.oidc_client_secret_reference)
        )
    try:
        try:
            claims = await OidcClient(settings).exchange_and_validate(
                code=payload.code,
                verifier=payload.code_verifier,
                transaction=transaction,
                client_secret=resolved_secret,
            )
        except (ValueError, OSError) as exc:
            raise HTTPException(401, "OIDC token validation failed") from exc
    finally:
        resolved_secret = None
    email = str(claims.get("email", "")).lower()
    user = await db.scalar(
        select(User).where(
            User.organization_id == organization.id,
            func.lower(User.email) == email,
        )
    )
    if not user and settings.oidc_jit_enabled:
        mapped_roles: list[Role] = []
        if provider_record:
            external_groups = set(claims.get("groups") or [])
            mappings = list(
                (
                    await db.scalars(
                        select(ExternalGroupRoleMapping).where(
                            ExternalGroupRoleMapping.organization_id == organization.id,
                            ExternalGroupRoleMapping.provider_id == provider_record.id,
                            ExternalGroupRoleMapping.external_group.in_(external_groups),
                            ExternalGroupRoleMapping.enabled.is_(True),
                        )
                    )
                ).all()
            )
            for mapping in mappings:
                role = await db.get(Role, mapping.role_id)
                if role and role.name != "Administrator":
                    mapped_roles.append(role)
        active_jit = bool(
            provider_record and not provider_record.jit_requires_approval and mapped_roles
        )
        user = User(
            organization_id=organization.id,
            name=str(claims.get("name") or email)[:160],
            email=email,
            password_hash=f"!oidc-only:{uuid4()}",
            status="active" if active_jit else "pending",
            must_change_password=False,
            roles=mapped_roles,
        )
        db.add(user)
        await db.flush()
        await write_audit(
            db,
            user,
            "auth.oidc_jit_provisioned",
            "user",
            user.id,
            metadata={
                "provider": "oidc",
                "status": user.status,
                "mapped_roles": len(mapped_roles),
            },
        )
        await db.commit()
        if not active_jit:
            raise HTTPException(403, "Account pending administrative approval")
    if not user or user.status != "active":
        raise HTTPException(401, "Authentication failed")
    refresh = await issue_refresh_token(db, user)
    _, raw_session, csrf = await SessionService.create(
        db,
        user,
        settings,
        authentication_method="oidc",
        authentication_strength=(
            "mfa"
            if {"mfa", "hwk", "fido", "webauthn"}.intersection(claims.get("amr") or [])
            else "single_factor"
        ),
    )
    await write_audit(db, user, "auth.oidc_login", "user", user.id)
    await db.commit()
    response.set_cookie(
        "cyberaudit_session",
        raw_session,
        httponly=True,
        secure=settings.secure_cookies,
        samesite="strict",
        max_age=settings.session_absolute_hours * 3600,
        path="/",
    )
    response.set_cookie(
        "cyberaudit_csrf",
        csrf,
        httponly=False,
        secure=settings.secure_cookies,
        samesite="strict",
        max_age=settings.session_absolute_hours * 3600,
        path="/",
    )
    return {
        "access_token": create_access_token(user),
        "refresh_token": refresh,
        "token_type": "bearer",
        "expires_in": settings.access_token_minutes * 60,
    }


@router.post("/auth/mfa/totp/enroll", status_code=201)
async def enroll_totp(
    payload: TotpEnrollment,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("mfa.manage")),
):
    provider = secret_provider()
    reference = SecretReference(payload.secret_reference)
    secret = await provider.resolve_reference(reference)
    try:
        if not verify_totp(secret, payload.code):
            raise HTTPException(422, "TOTP verification failed")
    finally:
        secret = ""
    factor = MfaFactor(
        organization_id=user.organization_id,
        user_id=user.id,
        factor_type="totp",
        label=payload.label,
        secret_reference=reference.uri,
        status="active",
        verified_at=datetime.now(timezone.utc),
    )
    db.add(factor)
    user.mfa_enabled = True
    await db.flush()
    await write_audit(db, user, "mfa.totp_enrolled", "mfa_factor", factor.id)
    await db.commit()
    return {"id": factor.id, "type": "totp", "status": "active", "label": factor.label}


@router.post("/auth/mfa/recovery-codes")
async def create_recovery_codes(
    payload: RecoveryCodeRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("mfa.manage")),
):
    if not user.mfa_enabled:
        raise HTTPException(409, "An active MFA factor is required")
    codes, hashes = generate_recovery_codes(payload.count)
    existing = list(
        (
            await db.scalars(
                select(RecoveryCode).where(
                    RecoveryCode.organization_id == user.organization_id,
                    RecoveryCode.user_id == user.id,
                    RecoveryCode.used_at.is_(None),
                )
            )
        ).all()
    )
    now = datetime.now(timezone.utc)
    for record in existing:
        record.used_at = now
    db.add_all(
        [
            RecoveryCode(
                organization_id=user.organization_id,
                user_id=user.id,
                code_hash=code_hash,
            )
            for code_hash in hashes
        ]
    )
    await write_audit(db, user, "mfa.recovery_codes_rotated", "user", user.id)
    await db.commit()
    return {
        "codes": codes,
        "warning": "These one-time recovery codes are shown only in this response.",
    }


@router.get("/auth/providers")
async def authentication_providers(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("authentication_providers.read")),
):
    rows = list(
        (
            await db.scalars(
                select(AuthenticationProvider).where(
                    AuthenticationProvider.organization_id == user.organization_id
                )
            )
        ).all()
    )
    return {"items": [serialize(row) for row in rows], "total": len(rows)}


@router.get("/auth/sessions")
async def sessions(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("sessions.read")),
):
    rows = list(
        (
            await db.scalars(
                select(UserSession)
                .where(
                    UserSession.organization_id == user.organization_id,
                    UserSession.user_id == user.id,
                )
                .order_by(UserSession.last_seen_at.desc())
                .limit(50)
            )
        ).all()
    )
    return {"items": [serialize(row) for row in rows], "total": len(rows)}


@router.delete("/auth/sessions/{session_id}", status_code=204)
async def revoke_session(
    session_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("sessions.manage")),
):
    session = await db.scalar(
        select(UserSession).where(
            UserSession.id == session_id,
            UserSession.organization_id == user.organization_id,
            UserSession.user_id == user.id,
        )
    )
    if not session:
        raise HTTPException(404, "Session not found")
    session.status = "revoked"
    session.revoked_at = datetime.now(timezone.utc)
    session.revoked_by = user.id
    session.revoke_reason = "user_requested"
    await write_audit(db, user, "session.revoked", "user_session", session.id)
    await db.commit()


@router.get("/feature-flags")
async def feature_flags(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("feature_flags.read")),
):
    rows = list(
        (
            await db.scalars(
                select(FeatureFlag).where(FeatureFlag.organization_id == user.organization_id)
            )
        ).all()
    )
    return {"items": [serialize(row) for row in rows], "total": len(rows)}


@router.post("/feature-flags", status_code=201)
async def create_feature_flag(
    payload: FeatureFlagPayload,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("feature_flags.manage")),
):
    if payload.edition and payload.edition not in EDITIONS:
        raise HTTPException(422, "Unknown product edition")
    flag = FeatureFlag(
        organization_id=user.organization_id,
        environment=get_settings().environment,
        created_by=user.id,
        **payload.model_dump(),
    )
    db.add(flag)
    await db.flush()
    await write_audit(db, user, "feature_flag.created", "feature_flag", flag.id)
    await db.commit()
    return serialize(flag)


@router.get("/license")
async def license_status(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("license.read")),
):
    record = await db.scalar(
        select(LicenseRecord)
        .where(LicenseRecord.organization_id == user.organization_id)
        .order_by(LicenseRecord.created_at.desc())
        .limit(1)
    )
    if not record:
        record = LicenseService.community(user.organization_id)
    return serialize(record)


@router.get("/telemetry/preview")
async def preview_telemetry(
    user: User = Depends(require_permission("telemetry.read")),
):
    return telemetry_preview(
        {
            "version": "0.2.0",
            "edition": "community",
            "operating_system": "not_collected_until_runtime",
            "health_status": "ok",
        }
    )


@router.patch("/telemetry")
async def configure_telemetry(
    payload: TelemetryUpdate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("telemetry.manage")),
):
    preference = await db.scalar(
        select(TelemetryPreference).where(
            TelemetryPreference.organization_id == user.organization_id
        )
    )
    if not preference:
        preference = TelemetryPreference(organization_id=user.organization_id)
        db.add(preference)
    preference.enabled = payload.enabled
    preference.allowed_categories = payload.allowed_categories if payload.enabled else []
    preference.last_preview = telemetry_preview(
        {
            "version": "0.2.0",
            "edition": "community",
            "operating_system": "not_collected_until_runtime",
            "health_status": "ok",
        }
    )
    preference.consented_by = user.id if payload.enabled else None
    preference.consented_at = datetime.now(timezone.utc) if payload.enabled else None
    await db.flush()
    await write_audit(db, user, "telemetry.configured", "telemetry_preference", preference.id)
    await db.commit()
    return serialize(preference)


@router.get("/operations/health")
async def operations_health(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("operations.read")),
):
    settings = get_settings()
    sessions_count = (
        await db.scalar(
            select(func.count())
            .select_from(UserSession)
            .where(
                UserSession.organization_id == user.organization_id,
                UserSession.status == "active",
            )
        )
        or 0
    )
    backups = (
        await db.scalar(
            select(func.count())
            .select_from(BackupRecord)
            .where(BackupRecord.organization_id == user.organization_id)
        )
        or 0
    )
    try:
        secret_health = await secret_provider(settings).health_check()
        secret_status = "healthy" if secret_health.healthy else "unavailable"
    except (RuntimeError, ValueError):
        secret_status = "unavailable"
    try:
        storage_health = await object_storage_provider(settings).health_check()
        storage_status = "healthy" if storage_health.get("healthy") else "unavailable"
    except (BotoCoreError, RuntimeError, ValueError):
        storage_status = "unavailable"
    return {
        "status": "ok",
        "environment": settings.environment,
        "configuration": ("production_validated" if settings.production_like else "development"),
        "authentication": settings.authentication_mode,
        "secret_provider": secret_status,
        "object_storage": storage_status,
        "runner": settings.runner_type,
        "active_sessions": sessions_count,
        "backup_records": backups,
        "backup_readiness": "unverified",
        "restore_readiness": "unverified",
    }


@router.get("/operations/backups")
async def backups(
    limit: int = Query(default=50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("backups.read")),
):
    rows = list(
        (
            await db.scalars(
                select(BackupRecord)
                .where(BackupRecord.organization_id == user.organization_id)
                .order_by(BackupRecord.created_at.desc())
                .limit(limit)
            )
        ).all()
    )
    return {"items": [serialize(row) for row in rows], "total": len(rows)}


@router.get("/operations/restores")
async def restores(
    limit: int = Query(default=50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("restores.read")),
):
    rows = list(
        (
            await db.scalars(
                select(RestoreRecord)
                .where(RestoreRecord.organization_id == user.organization_id)
                .order_by(RestoreRecord.created_at.desc())
                .limit(limit)
            )
        ).all()
    )
    return {"items": [serialize(row) for row in rows], "total": len(rows)}


@router.get("/operations/slos")
async def slos(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("operations.read")),
):
    rows = list(
        (
            await db.scalars(
                select(ServiceLevelObjective).where(
                    ServiceLevelObjective.organization_id == user.organization_id
                )
            )
        ).all()
    )
    return {"items": [serialize(row) for row in rows], "total": len(rows)}


def _verify_step_up(token: str | None, user: User) -> bool:
    if not token:
        return False
    try:
        claims = decode_token(token, "step_up")
    except HTTPException:
        return False
    methods = set(claims.get("amr") or [])
    return (
        claims.get("sub") == user.id
        and claims.get("org") == user.organization_id
        and bool({"webauthn", "phishing_resistant_oidc"}.intersection(methods))
    )


@router.post("/auth/webauthn/registration/options")
async def webauthn_registration_options(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("mfa.manage")),
):
    try:
        challenge_id, options = await WebAuthnService(get_settings()).registration_options(db, user)
    except (ValueError, RuntimeError) as exc:
        webauthn_registration_total.labels("denied").inc()
        raise HTTPException(409, "WebAuthn registration is unavailable") from exc
    return {"challenge_id": challenge_id, "public_key": options}


@router.post("/auth/webauthn/registration/verify", status_code=201)
async def webauthn_registration_verify(
    payload: WebAuthnRegistrationFinish,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("mfa.manage")),
):
    try:
        factor = await WebAuthnService(get_settings()).verify_registration(
            db,
            user,
            challenge_id=payload.challenge_id,
            label=payload.label,
            credential=payload.credential,
        )
    except Exception as exc:
        webauthn_registration_total.labels("failed").inc()
        await write_audit(db, user, "webauthn.registration_failed", "mfa_factor", None, "denied")
        await db.commit()
        raise HTTPException(400, "WebAuthn registration verification failed") from exc
    webauthn_registration_total.labels("success").inc()
    await write_audit(db, user, "webauthn.registered", "mfa_factor", factor.id)
    await db.commit()
    return {
        "id": factor.id,
        "label": factor.label,
        "status": factor.status,
        "created_at": factor.created_at,
    }


@router.post("/auth/webauthn/step-up/options")
async def webauthn_step_up_options(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("mfa.manage")),
):
    try:
        challenge_id, options = await WebAuthnService(get_settings()).authentication_options(
            db, user, "step_up"
        )
    except (ValueError, RuntimeError) as exc:
        webauthn_authentication_total.labels("denied").inc()
        raise HTTPException(409, "WebAuthn step-up is unavailable") from exc
    return {"challenge_id": challenge_id, "public_key": options}


@router.post("/auth/webauthn/step-up/verify")
async def webauthn_step_up_verify(
    payload: WebAuthnAuthenticationFinish,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("mfa.manage")),
):
    try:
        factor = await WebAuthnService(get_settings()).verify_authentication(
            db,
            user,
            challenge_id=payload.challenge_id,
            credential=payload.credential,
            purpose="step_up",
        )
    except Exception as exc:
        webauthn_authentication_total.labels("failed").inc()
        await write_audit(db, user, "webauthn.authentication_failed", "mfa_factor", None, "denied")
        await db.commit()
        raise HTTPException(401, "WebAuthn assertion verification failed") from exc
    webauthn_authentication_total.labels("success").inc()
    await write_audit(db, user, "webauthn.step_up", "mfa_factor", factor.id)
    await db.commit()
    return {
        "step_up_token": create_step_up_token(user, "webauthn"),
        "token_type": "bearer",
        "expires_in": 300,
    }


@router.delete("/auth/webauthn/credentials/{factor_id}", status_code=204)
async def webauthn_revoke(
    factor_id: str,
    payload: WebAuthnRevoke,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("mfa.manage")),
):
    if not _verify_step_up(payload.step_up_token, user):
        raise HTTPException(403, "Phishing-resistant step-up is required")
    factor = await db.scalar(
        select(MfaFactor).where(
            MfaFactor.id == factor_id,
            MfaFactor.organization_id == user.organization_id,
            MfaFactor.user_id == user.id,
            MfaFactor.factor_type == "webauthn",
            MfaFactor.status == "active",
        )
    )
    if not factor:
        raise HTTPException(404, "WebAuthn credential not found")
    active_count = (
        await db.scalar(
            select(func.count())
            .select_from(MfaFactor)
            .where(
                MfaFactor.organization_id == user.organization_id,
                MfaFactor.user_id == user.id,
                MfaFactor.status == "active",
            )
        )
        or 0
    )
    if get_settings().mfa_required and active_count <= 1:
        raise HTTPException(409, "Cannot revoke the final active MFA factor")
    factor.status = "revoked"
    factor.revoked_at = datetime.now(timezone.utc)
    factor.revoked_by = user.id
    await write_audit(db, user, "webauthn.revoked", "mfa_factor", factor.id)
    await db.commit()
    return Response(status_code=204)


@router.get("/operations/dead-letters")
async def dead_letters(
    status_filter: str | None = Query(default=None, alias="status", max_length=30),
    limit: int = Query(default=50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("dead_letters.read")),
):
    statement = select(DeadLetterMessage).where(
        DeadLetterMessage.organization_id == user.organization_id
    )
    if status_filter:
        statement = statement.where(DeadLetterMessage.status == status_filter)
    rows = list(
        (
            await db.scalars(
                statement.order_by(DeadLetterMessage.last_failed_at.desc()).limit(limit)
            )
        ).all()
    )
    return {"items": [serialize(row) for row in rows], "total": len(rows)}


@router.get("/operations/dead-letters/{message_id}")
async def dead_letter_detail(
    message_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("dead_letters.read")),
):
    row = await db.scalar(
        select(DeadLetterMessage).where(
            DeadLetterMessage.id == message_id,
            DeadLetterMessage.organization_id == user.organization_id,
        )
    )
    if not row:
        raise HTTPException(404, "Dead-letter message not found")
    return serialize(row)


@router.post("/operations/dead-letters/{message_id}/{action}")
async def dead_letter_action(
    message_id: str,
    action: str,
    payload: DeadLetterAction,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("dead_letters.manage")),
):
    if action not in {"acknowledge", "replay", "discard"}:
        raise HTTPException(404, "Unsupported dead-letter action")
    validated_action = cast(Literal["acknowledge", "replay", "discard"], action)
    row = await db.scalar(
        select(DeadLetterMessage).where(
            DeadLetterMessage.id == message_id,
            DeadLetterMessage.organization_id == user.organization_id,
        )
    )
    if not row:
        raise HTTPException(404, "Dead-letter message not found")
    try:
        await DeadLetterService().transition(
            db,
            row,
            action=validated_action,
            actor_id=user.id,
            step_up_verified=_verify_step_up(payload.step_up_token, user),
        )
    except (ValueError, PermissionError, RuntimeError) as exc:
        dead_letter_replays_total.labels("denied").inc()
        raise HTTPException(409, str(exc)) from exc
    await write_audit(db, user, f"dead_letter.{action}", "dead_letter_message", row.id)
    await db.commit()
    if action == "replay":
        dead_letter_replays_total.labels("success").inc()
    return serialize(row)


@router.get("/operations/production-readiness")
async def production_readiness(
    environment: str = Query(default="production-like", pattern=r"^[a-z0-9-]{2,40}$"),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission("operations.read")),
):
    result = await ProductionReadinessGate(get_settings()).evaluate(
        db, user.organization_id, environment
    )
    production_readiness_blockers.set(len(result["blockers"]))
    return result
