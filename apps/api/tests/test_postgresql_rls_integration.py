"""Opt-in PostgreSQL RLS enforcement test.

Set CYBERAUDIT_RLS_TEST_DATABASE_URL to a disposable migrated PostgreSQL
database. The suite never runs against an unknown/default database.
"""

from __future__ import annotations

import os

import asyncpg
import pytest


def _dsn() -> str:
    configured = os.getenv("CYBERAUDIT_RLS_TEST_DATABASE_URL")
    if not configured:
        pytest.skip("CYBERAUDIT_RLS_TEST_DATABASE_URL is not configured")
    if "127.0.0.1" not in configured and "localhost" not in configured:
        pytest.skip("RLS integration test is restricted to an explicit local database")
    return configured.replace("postgresql+asyncpg://", "postgresql://")


@pytest.mark.asyncio
async def test_runtime_role_denies_missing_and_cross_tenant_context() -> None:
    connection = await asyncpg.connect(_dsn())
    try:
        organization_id = await connection.fetchval("SELECT organization_id FROM assets LIMIT 1")
        assert organization_id
        transaction = connection.transaction()
        await transaction.start()
        try:
            await connection.execute("SET LOCAL ROLE cyberaudit_runtime")
            assert await connection.fetchval("SELECT count(*) FROM assets") == 0
            assert await connection.fetchval("SELECT count(*) FROM organizations") == 0
            await connection.fetchval(
                "SELECT set_config('app.current_organization_id', $1, true)",
                str(organization_id),
            )
            assert await connection.fetchval("SELECT count(*) FROM assets") > 0
            assert await connection.fetchval("SELECT count(*) FROM organizations") == 1
            assert await connection.fetchval("SELECT count(*) FROM roles") > 0
            assert await connection.fetchval("SELECT count(*) FROM permissions") > 0
            assert await connection.fetchval("SELECT count(*) FROM user_roles") > 0
            assert (
                await connection.fetchval(
                    "SELECT count(*) FROM assets WHERE organization_id <> $1", organization_id
                )
                == 0
            )
            with pytest.raises(asyncpg.InsufficientPrivilegeError):
                await connection.execute("""
                    UPDATE assets
                    SET organization_id = '00000000-0000-4000-8000-000000000099'
                    WHERE id = (SELECT id FROM assets LIMIT 1)
                    """)
        finally:
            await transaction.rollback()
    finally:
        await connection.close()
