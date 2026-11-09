"""Idempotent provisioning of the global RBAC catalogue.

The desktop migration sidecar executes this with the database owner connection
before the lower-privileged API starts. Runtime requests therefore never need
write access to the global roles and permissions tables.
"""

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cyberaudit.models import Permission, Role
from cyberaudit.rbac_catalog import ALL_PERMISSIONS, PLATFORM_PERMISSION, ROLE_DEFINITIONS
from cyberaudit.seed import ROLE_CODES
from cyberaudit.seed_phase3 import ROLE_PERMISSIONS as PHASE3_ROLE_PERMISSIONS


async def ensure_rbac(db: AsyncSession) -> None:
    """Create or reconcile the fixed application RBAC catalogue."""

    existing = {
        permission.code: permission for permission in (await db.scalars(select(Permission))).all()
    }
    for code in (*ALL_PERMISSIONS, PLATFORM_PERMISSION):
        if code not in existing:
            existing[code] = Permission(
                code=code,
                description=code.replace(".", " ").title(),
            )
            db.add(existing[code])
    await db.flush()

    definitions: dict[str, set[str]] = {
        name: set(codes) for name, codes in ROLE_DEFINITIONS.items()
    }
    for legacy in ("Auditor", "Reviewer", "Client"):
        definitions[legacy] = set(ROLE_CODES.get(legacy, [])) | set(
            PHASE3_ROLE_PERMISSIONS.get(legacy, [])
        )
    roles = {role.name: role for role in (await db.scalars(select(Role))).all()}
    for name, codes in definitions.items():
        role = roles.get(name)
        if role is None:
            role = Role(name=name, description=f"CyberAudit {name}")
            db.add(role)
            roles[name] = role
        assigned = {permission.code for permission in role.permissions}
        for code in sorted(codes - assigned):
            if code in existing:
                role.permissions.append(existing[code])
    await db.flush()
