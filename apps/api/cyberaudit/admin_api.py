"""Real administration: roles, user lifecycle, tenant creation and first-run bootstrap.

Security properties:
- every mutation requires an explicit permission and is audited;
- a user can only be managed inside the caller's own organization;
- tenant creation needs the dedicated ``platform.manage`` permission, which only
  the "Platform Administrator" role carries;
- first-run bootstrap is only possible while the database has no users AND the
  operator supplied the one-time ``BOOTSTRAP_TOKEN`` secret out of band.
"""

from __future__ import annotations

import hmac
from datetime import datetime, timezone
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from cyberaudit.audit import write_audit
from cyberaudit.config import get_settings
from cyberaudit.db import get_db
from cyberaudit.enterprise_auth import SessionService
from cyberaudit.models import Organization, Permission, RefreshToken, Role, User
from cyberaudit.password_policy import validate_password_policy
from cyberaudit.provisioning import provision_assessment_catalog
from cyberaudit.rbac_catalog import (
    ALL_PERMISSIONS,
    PLATFORM_PERMISSION,
    PLATFORM_ROLE,
    ROLE_DEFINITIONS,
)
from cyberaudit.rls import set_tenant_context
from cyberaudit.security import hash_password, require_permission
from cyberaudit.seed import ROLE_CODES
from cyberaudit.seed_phase3 import ROLE_PERMISSIONS as PHASE3_ROLE_PERMISSIONS

router = APIRouter(prefix="/api/v1", tags=["administration"])

USER_STATUSES = {"active", "disabled"}


def _password(value: str, email: str) -> str:
    try:
        return validate_password_policy(value, email=email)
    except ValueError as exc:
        raise ValueError(str(exc)) from exc


async def ensure_rbac(db: AsyncSession) -> None:
    """Idempotently make sure every known permission and role exists."""
    existing = {p.code: p for p in (await db.scalars(select(Permission))).all()}
    for code in (*ALL_PERMISSIONS, PLATFORM_PERMISSION):
        if code not in existing:
            existing[code] = Permission(code=code, description=code.replace(".", " ").title())
            db.add(existing[code])
    await db.flush()
    definitions: dict[str, set[str]] = {n: set(c) for n, c in ROLE_DEFINITIONS.items()}
    # Legacy built-in roles keep their historical permission sets (plus phase-3 additions).
    for legacy in ("Auditor", "Reviewer", "Client"):
        definitions[legacy] = set(ROLE_CODES.get(legacy, [])) | set(
            PHASE3_ROLE_PERMISSIONS.get(legacy, [])
        )
    roles = {r.name: r for r in (await db.scalars(select(Role))).all()}
    for name, codes in definitions.items():
        role = roles.get(name)
        if role is None:
            role = Role(name=name, description=f"CyberAudit {name}")
            db.add(role)
            roles[name] = role
        have = {p.code for p in role.permissions}
        for code in sorted(codes - have):
            if code in existing:
                role.permissions.append(existing[code])
    await db.flush()


class RoleRead(BaseModel):
    name: str
    description: str
    permissions: list[str]


@router.get("/roles")
async def list_roles(
    user: User = Depends(require_permission("users.manage")),
    db: AsyncSession = Depends(get_db),
):
    can_platform = any(
        p.code == PLATFORM_PERMISSION for role in user.roles for p in role.permissions
    )
    roles = list((await db.scalars(select(Role).order_by(Role.name))).all())
    items = [
        RoleRead(
            name=role.name,
            description=role.description,
            permissions=sorted(p.code for p in role.permissions),
        )
        for role in roles
        # Only platform administrators may see/assign the platform role.
        if can_platform or role.name != PLATFORM_ROLE
    ]
    return {"items": items, "total": len(items), "page": 1, "page_size": len(items)}


class UserPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str | None = Field(default=None, min_length=2, max_length=160)
    status: str | None = None
    role: str | None = None

    @field_validator("status")
    @classmethod
    def valid_status(cls, value: str | None) -> str | None:
        if value is not None and value not in USER_STATUSES:
            raise ValueError("status must be 'active' or 'disabled'")
        return value


class PasswordReset(BaseModel):
    model_config = ConfigDict(extra="forbid")
    password: str = Field(min_length=14, max_length=128)


async def _managed_user(db: AsyncSession, caller: User, user_id: str) -> User:
    target = await db.scalar(
        select(User).where(
            User.id == user_id,
            User.organization_id == caller.organization_id,
            User.deleted_at.is_(None),
        )
    )
    if not target:
        raise HTTPException(404, "User not found")
    return target


async def _revoke_all(db: AsyncSession, target: User, actor: User) -> int:
    revoked = await SessionService.revoke_all(db, target, actor.id)
    tokens = (
        await db.scalars(
            select(RefreshToken).where(
                RefreshToken.user_id == target.id, RefreshToken.revoked_at.is_(None)
            )
        )
    ).all()
    now = datetime.now(timezone.utc)
    for token in tokens:
        token.revoked_at = now
    return revoked + len(tokens)


async def _role_for(db: AsyncSession, caller: User, name: str) -> Role:
    role = await db.scalar(select(Role).where(Role.name == name))
    if not role:
        raise HTTPException(422, "Unknown role")
    caller_codes = {p.code for r in caller.roles for p in r.permissions}
    if name == PLATFORM_ROLE and PLATFORM_PERMISSION not in caller_codes:
        raise HTTPException(403, "Only platform administrators can assign this role")
    return role


@router.patch("/users/{user_id}")
async def update_user(
    user_id: str,
    payload: UserPatch,
    caller: User = Depends(require_permission("users.manage")),
    db: AsyncSession = Depends(get_db),
):
    target = await _managed_user(db, caller, user_id)
    changes: dict[str, str] = {}
    if payload.name is not None and payload.name != target.name:
        target.name = payload.name
        changes["name"] = "changed"
    if payload.role is not None:
        role = await _role_for(db, caller, payload.role)
        previous = sorted(r.name for r in target.roles)
        if previous != [role.name]:
            if target.id == caller.id:
                raise HTTPException(409, "You cannot change your own role")
            target.roles = [role]
            changes["role"] = f"{','.join(previous)}->{role.name}"
    if payload.status is not None and payload.status != target.status:
        if target.id == caller.id:
            raise HTTPException(409, "You cannot disable your own account")
        target.status = payload.status
        changes["status"] = payload.status
        if payload.status == "disabled":
            await _revoke_all(db, target, caller)
    await write_audit(db, caller, "user.updated", "user", target.id, metadata=changes)
    await db.commit()
    await db.refresh(target)
    return {
        "id": target.id,
        "name": target.name,
        "email": target.email,
        "status": target.status,
        "roles": sorted(r.name for r in target.roles),
    }


@router.post("/users/{user_id}/reset-password", status_code=204)
async def reset_password(
    user_id: str,
    payload: PasswordReset,
    caller: User = Depends(require_permission("users.manage")),
    db: AsyncSession = Depends(get_db),
):
    target = await _managed_user(db, caller, user_id)
    try:
        _password(payload.password, target.email)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    target.password_hash = hash_password(payload.password)
    target.must_change_password = True
    target.failed_login_attempts = 0
    target.locked_until = None
    await _revoke_all(db, target, caller)
    await write_audit(db, caller, "user.password_reset", "user", target.id)
    await db.commit()


@router.post("/users/{user_id}/revoke-sessions")
async def revoke_sessions(
    user_id: str,
    caller: User = Depends(require_permission("users.manage")),
    db: AsyncSession = Depends(get_db),
):
    target = await _managed_user(db, caller, user_id)
    count = await _revoke_all(db, target, caller)
    await write_audit(db, caller, "user.sessions_revoked", "user", target.id)
    await db.commit()
    return {"revoked": count}


class TenantCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=2, max_length=160)
    slug: str = Field(pattern=r"^[a-z0-9-]+$", min_length=2, max_length=80)
    timezone: str = "Europe/Lisbon"
    locale: str = "pt-PT"
    admin_name: str = Field(min_length=2, max_length=160)
    admin_email: EmailStr
    admin_password: str = Field(min_length=14, max_length=128)


async def _create_tenant(
    db: AsyncSession, payload: TenantCreate, admin_role_name: str
) -> tuple[Organization, User]:
    try:
        _password(payload.admin_password, str(payload.admin_email))
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    if payload.locale not in {"pt-PT", "en"}:
        raise HTTPException(422, "Unsupported locale")
    organization = Organization(
        id=str(uuid4()),
        name=payload.name,
        slug=payload.slug,
        timezone=payload.timezone,
        locale=payload.locale,
    )
    # Scope the transaction to the NEW tenant so RLS WITH CHECK policies accept
    # the inserts; the setting is transaction-local and cleared on commit.
    await set_tenant_context(db, organization.id)
    role = await db.scalar(select(Role).where(Role.name == admin_role_name))
    if not role:
        raise HTTPException(500, "Administrator role is not provisioned")
    admin = User(
        organization_id=organization.id,
        name=payload.admin_name,
        email=str(payload.admin_email).lower(),
        password_hash=hash_password(payload.admin_password),
        must_change_password=True,
        roles=[role],
    )
    try:
        db.add(organization)
        await db.flush()
        db.add(admin)
        await db.flush()
        await provision_assessment_catalog(db, organization.id, admin.id)
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(
            409, "Organization slug or administrator e-mail already exists"
        ) from exc
    return organization, admin


@router.post("/platform/organizations", status_code=201)
async def create_organization(
    payload: TenantCreate,
    caller: User = Depends(require_permission(PLATFORM_PERMISSION)),
    db: AsyncSession = Depends(get_db),
):
    caller_org, caller_id, caller_email = caller.organization_id, caller.id, caller.email
    organization, admin = await _create_tenant(db, payload, "Administrator")
    result = {
        "id": organization.id,
        "name": organization.name,
        "slug": organization.slug,
        "administrator": {"id": admin.id, "email": admin.email},
    }
    await db.commit()
    # Audit in the caller's tenant (separate transaction, caller's context).
    await set_tenant_context(db, caller_org)
    caller = await db.get(User, caller_id) or caller
    await write_audit(
        db,
        caller,
        "organization.created",
        "organization",
        result["id"],
        metadata={"slug": result["slug"], "caller_email": caller_email},
    )
    await db.commit()
    return result


class SetupStatus(BaseModel):
    initialized: bool
    bootstrap_enabled: bool


async def _user_count(db: AsyncSession) -> int:
    return int(await db.scalar(select(func.count()).select_from(User)) or 0)


@router.get("/setup/status", response_model=SetupStatus)
async def setup_status(db: AsyncSession = Depends(get_db)):
    settings = get_settings()
    initialized = await _user_count(db) > 0
    return SetupStatus(
        initialized=initialized,
        bootstrap_enabled=(not initialized) and bool(settings.bootstrap_token),
    )


class SetupPayload(TenantCreate):
    bootstrap_token: str = Field(min_length=16, max_length=256)


@router.post("/setup/initialize", status_code=201)
async def initialize(payload: SetupPayload, db: AsyncSession = Depends(get_db)):
    settings = get_settings()
    expected = settings.bootstrap_token
    # Same error for "disabled", "already initialized" and "wrong token": no oracle.
    denied = HTTPException(403, "Setup is not available")
    if not expected or await _user_count(db) > 0:
        raise denied
    if not hmac.compare_digest(payload.bootstrap_token.encode(), expected.encode()):
        raise denied
    await ensure_rbac(db)
    organization, admin = await _create_tenant(db, payload, PLATFORM_ROLE)
    admin.must_change_password = False
    await db.commit()
    await set_tenant_context(db, organization.id)
    await write_audit(db, admin, "setup.initialized", "organization", organization.id)
    await db.commit()
    return {"organization_id": organization.id, "administrator": admin.email}
