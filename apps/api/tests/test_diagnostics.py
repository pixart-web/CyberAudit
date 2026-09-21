"""Diagnostic bundle generator (Phase 10.4.1, section 49).

Verifies the bundle is genuinely privacy-safe: it never carries a secret
value even when one is deliberately planted in settings, it only ever
counts (never lists) tenant rows, and it stays scoped to the caller's own
organization.
"""

from __future__ import annotations

import pytest

from cyberaudit.config import Settings
from cyberaudit.diagnostics import ALLOWLISTED_SETTINGS_FIELDS, build_diagnostic_bundle
from cyberaudit.models import (  # noqa: E501
    Asset,
    Criticality,
    Engagement,
    EngagementMode,
    Organization,
    User,
)


@pytest.mark.asyncio
async def test_bundle_never_leaks_secret_configuration_values(db):
    organization = Organization(name="Diag Tenant", slug="diag-tenant")
    db.add(organization)
    await db.flush()
    user = User(
        organization_id=organization.id,
        name="Diag Admin",
        email="diag-admin@example.invalid",
        password_hash="",  # noqa: S106 - authentication is not exercised here
    )
    db.add(user)
    await db.flush()

    settings = Settings(
        jwt_secret="super-secret-jwt-value-should-never-leak",  # noqa: S106
        encryption_key="super-secret-encryption-key-should-never-leak",  # noqa: S106
        database_url="postgresql://user:hunter2@db.internal/cyberaudit",
    )

    bundle = await build_diagnostic_bundle(db, settings, user)
    serialized = str(bundle.configuration) + str(bundle.health) + str(bundle.ai_runtime)

    assert "super-secret-jwt-value-should-never-leak" not in serialized
    assert "super-secret-encryption-key-should-never-leak" not in serialized
    assert "hunter2" not in serialized
    assert "jwt_secret" not in bundle.configuration
    assert "encryption_key" not in bundle.configuration
    assert "database_url" not in bundle.configuration


@pytest.mark.asyncio
async def test_bundle_allowlist_never_names_a_credential_field():
    # `secret_provider` is an enum naming *which* secret backend is
    # configured (environment/vault/aws/...), never a secret value -- it is
    # the one intentional exception to the naming heuristic below.
    known_safe_exceptions = {"secret_provider"}
    forbidden_substrings = ("secret", "password", "token", "key", "credential")
    for field_name in ALLOWLISTED_SETTINGS_FIELDS:
        if field_name in known_safe_exceptions:
            continue
        lowered = field_name.lower()
        assert not any(term in lowered for term in forbidden_substrings), field_name


@pytest.mark.asyncio
async def test_bundle_counts_are_scoped_to_the_callers_organization(db):
    tenant_a = Organization(name="Tenant A", slug="tenant-a-diag")
    tenant_b = Organization(name="Tenant B", slug="tenant-b-diag")
    db.add_all([tenant_a, tenant_b])
    await db.flush()

    user_a = User(
        organization_id=tenant_a.id,
        name="A Admin",
        email="a-admin@example.invalid",
        password_hash="",  # noqa: S106
    )
    db.add(user_a)
    engagement_a = Engagement(
        organization_id=tenant_a.id,
        client_id="client-a",
        name="Tenant A Assessment",
        code="DIAG-A-001",
        mode=EngagementMode.CLIENT,
    )
    engagement_b = Engagement(
        organization_id=tenant_b.id,
        client_id="client-b",
        name="Tenant B Assessment",
        code="DIAG-B-001",
        mode=EngagementMode.CLIENT,
    )
    db.add_all([engagement_a, engagement_b])
    await db.flush()
    db.add(
        Asset(
            organization_id=tenant_a.id,
            engagement_id=engagement_a.id,
            name="tenant-a-asset",
            asset_type="host",
            identifier="tenant-a-asset-1",
            criticality=Criticality.LOW,
        )
    )
    db.add(
        Asset(
            organization_id=tenant_b.id,
            engagement_id=engagement_b.id,
            name="tenant-b-asset",
            asset_type="host",
            identifier="tenant-b-asset-1",
            criticality=Criticality.LOW,
        )
    )
    await db.flush()

    bundle = await build_diagnostic_bundle(db, Settings(), user_a)

    assert bundle.organization_id == tenant_a.id
    assert bundle.counts["assets"] == 1


@pytest.mark.asyncio
async def test_bundle_includes_disclosure_text(db):
    organization = Organization(name="Disclosure Tenant", slug="disclosure-tenant")
    db.add(organization)
    await db.flush()
    user = User(
        organization_id=organization.id,
        name="Disclosure Admin",
        email="disclosure-admin@example.invalid",
        password_hash="",  # noqa: S106
    )
    db.add(user)
    await db.flush()

    bundle = await build_diagnostic_bundle(db, Settings(), user)
    assert "never contains finding" in bundle.disclosure
