"""Operator CLI for installations that already contain data.

    python -m cyberaudit.admin_cli ensure-rbac
    python -m cyberaudit.admin_cli provision-catalog --org <slug>
    python -m cyberaudit.admin_cli rotate-password --email <address>

``rotate-password`` reads the new password from a hidden prompt (or the
``NEW_PASSWORD`` environment variable for automation) and never prints it.
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import os
import sys

from sqlalchemy import select

from cyberaudit.admin_api import _revoke_all, ensure_rbac
from cyberaudit.db import SessionLocal
from cyberaudit.models import Organization, User
from cyberaudit.password_policy import validate_password_policy
from cyberaudit.provisioning import provision_assessment_catalog
from cyberaudit.rls import set_tenant_context
from cyberaudit.security import hash_password


async def _ensure_rbac() -> None:
    async with SessionLocal() as db:
        await ensure_rbac(db)
        await db.commit()
    print("RBAC permissions and roles are provisioned.")


async def _provision(slug: str) -> None:
    async with SessionLocal() as db:
        org = await db.scalar(select(Organization).where(Organization.slug == slug))
        if not org:
            sys.exit(f"Unknown organization: {slug}")
        await set_tenant_context(db, org.id)
        admin = await db.scalar(select(User).where(User.organization_id == org.id))
        if not admin:
            sys.exit("Organization has no users; run setup first.")
        added = await provision_assessment_catalog(db, org.id, admin.id)
        await db.commit()
    print(f"Provisioned {added} scan profile(s) for {slug}.")


async def _rotate(email: str) -> None:
    password = os.environ.get("NEW_PASSWORD") or getpass.getpass("New password: ")
    try:
        validate_password_policy(password, email=email)
    except ValueError as exc:
        sys.exit(f"Rejected: {exc}")
    async with SessionLocal() as db:
        user = await db.scalar(select(User).where(User.email == email.lower()))
        if not user:
            sys.exit("No such user.")
        await set_tenant_context(db, user.organization_id)
        user.password_hash = hash_password(password)
        user.must_change_password = True
        user.failed_login_attempts = 0
        user.locked_until = None
        await _revoke_all(db, user, user)
        await db.commit()
    print("Password rotated; all sessions revoked; change required at next login.")


def main() -> None:
    parser = argparse.ArgumentParser(prog="cyberaudit.admin_cli")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("ensure-rbac")
    provision = sub.add_parser("provision-catalog")
    provision.add_argument("--org", required=True)
    rotate = sub.add_parser("rotate-password")
    rotate.add_argument("--email", required=True)
    args = parser.parse_args()
    if args.command == "ensure-rbac":
        asyncio.run(_ensure_rbac())
    elif args.command == "provision-catalog":
        asyncio.run(_provision(args.org))
    else:
        asyncio.run(_rotate(args.email))


if __name__ == "__main__":
    main()
