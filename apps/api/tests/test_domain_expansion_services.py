from datetime import datetime, timezone

import pytest
from pydantic import ValidationError
from sqlalchemy import select

from cyberaudit.domain_expansion_adapters import ADAPTER_CODES, EnterpriseImportConfiguration
from cyberaudit.domain_expansion_api import ConnectorPayload
from cyberaudit.domain_expansion_models import ConnectorExecution, EnterpriseConnector
from cyberaudit.domain_expansion_services import (
    ConnectorConfiguration,
    ZeroTrustEngine,
    ZeroTrustEvaluationRequest,
    cloud_risk_factors,
    detect_change,
    identity_risk_factors,
    sanitize_external_data,
    validate_secret_reference,
)
from cyberaudit.domain_expansion_worker import connector_execution_allowed
from cyberaudit.models import Organization, User


def test_connector_configuration_is_read_only_and_closed() -> None:
    valid = ConnectorConfiguration(
        connector_type="entra_id",
        provider="microsoft",
        requested_permissions=["directory.read.all"],
    )
    assert valid.read_only is True
    with pytest.raises(ValidationError):
        ConnectorConfiguration(connector_type="entra_id", provider="microsoft", read_only=False)
    with pytest.raises(ValidationError):
        ConnectorConfiguration(connector_type="custom_python", provider="unknown")


def test_only_secret_manager_references_are_accepted() -> None:
    assert validate_secret_reference("vault://cyberaudit/entra/demo") == (
        "vault://cyberaudit/entra/demo"
    )
    assert validate_secret_reference("development://demo-entra") == ("development://demo-entra")
    with pytest.raises(ValueError):
        validate_secret_reference("plain-text-client-secret")


def test_external_payload_is_recursively_sanitized() -> None:
    sanitized = sanitize_external_data(
        {
            "name": "tenant",
            "client_secret": "never-store-this",
            "nested": {"note": "password=unsafe token=also-unsafe"},
        }
    )
    assert sanitized["client_secret"] == "[REDACTED]"
    assert "unsafe" not in sanitized["nested"]["note"]


def test_change_detection_is_stable_and_secret_safe() -> None:
    first = detect_change(
        "org-1",
        "cloud",
        "resource-1",
        {"public": False, "token": "one"},
        {"public": False, "token": "two"},
    )
    repeated = detect_change(
        "org-1",
        "cloud",
        "resource-1",
        {"public": False, "token": "three"},
        {"public": False, "token": "four"},
    )
    assert first.changed is False
    assert first.fingerprint == repeated.fingerprint
    assert "token" not in first.changed_fields


def test_zero_trust_unknowns_reduce_confidence_not_score() -> None:
    result = ZeroTrustEngine().evaluate(
        ZeroTrustEvaluationRequest(
            subject_type="organization",
            facts={
                "identity": {"mfa": True, "legacy_auth_blocked": True},
                "device": {"managed": None},
            },
        )
    )
    assert result.score == 100
    assert result.confidence < 0.35
    assert result.status == "insufficient_evidence"
    assert "device.managed" in result.unknown_factors
    assert len(result.dimensions) == 8


def test_zero_trust_is_deterministic_and_explainable() -> None:
    request = ZeroTrustEvaluationRequest(
        subject_type="identity",
        subject_id="identity-1",
        facts={
            "identity": {"mfa": True, "privilege_minimized": False},
            "device": {"managed": True, "encrypted": True},
            "session": {"risk_evaluated": True},
            "application": {"approved": True},
            "network": {"segmented": False},
            "workload": {"least_privilege": True},
            "data": {"classified": True},
            "control": {"monitored": True},
        },
    )
    first = ZeroTrustEngine().evaluate(request)
    second = ZeroTrustEngine().evaluate(request)
    assert first.score == second.score
    assert first.confidence == 1
    assert any(item["factor"] == "mfa" for item in first.factors)


def test_identity_and_cloud_risk_factors() -> None:
    identity_score, identity_reasons = identity_risk_factors(
        privileged=True,
        mfa_enforced="false",
        enabled=True,
        stale_days=120,
        guest=False,
        owner=None,
    )
    cloud_score, cloud_reasons = cloud_risk_factors(
        public_exposure=True,
        criticality="critical",
        encryption="false",
        logging="false",
        wildcard_permissions=True,
    )
    assert identity_score == 95
    assert "mfa_not_enforced" in identity_reasons
    assert cloud_score == 100
    assert "public_exposure" in cloud_reasons


def test_enterprise_adapter_registry_is_closed_and_configuration_strict() -> None:
    assert len(ADAPTER_CODES) == len(set(ADAPTER_CODES))
    assert all(code.startswith("cyberaudit.") for code in ADAPTER_CODES)
    with pytest.raises(ValidationError):
        EnterpriseImportConfiguration.model_validate(
            {"scenario": "demo", "record_count": 1, "command": "whoami"}
        )


def test_connector_api_rejects_plaintext_and_extra_fields() -> None:
    with pytest.raises(ValidationError):
        ConnectorPayload.model_validate(
            {
                "connector_type": "aws",
                "provider": "aws",
                "name": "Production AWS",
                "secret_reference": "plaintext-secret",
            }
        )
    with pytest.raises(ValidationError):
        ConnectorPayload.model_validate(
            {
                "connector_type": "aws",
                "provider": "aws",
                "name": "Production AWS",
                "command": "aws configure",
            }
        )


def test_worker_revalidation_rejects_cross_tenant_and_mutable_connector() -> None:
    execution = ConnectorExecution(
        organization_id="tenant-alpha",
        connector_id="connector-1",
        execution_type="incremental_sync",
        idempotency_key="a" * 64,
        requested_by="user-1",
    )
    connector = EnterpriseConnector(
        id="connector-1",
        organization_id="tenant-beta",
        connector_type="aws",
        provider="aws",
        name="AWS",
        created_by="user-2",
        status="active",
        read_only=True,
    )
    assert not connector_execution_allowed(execution, connector)
    connector.organization_id = "tenant-alpha"
    connector.read_only = False
    assert not connector_execution_allowed(execution, connector)
    connector.read_only = True
    assert connector_execution_allowed(execution, connector)


@pytest.mark.asyncio
async def test_connector_inventory_is_tenant_isolated(db) -> None:
    organizations = [
        Organization(name="Alpha", slug="domain-alpha"),
        Organization(name="Beta", slug="domain-beta"),
    ]
    db.add_all(organizations)
    await db.flush()
    users = [
        User(
            organization_id=organization.id,
            name=f"{organization.name} Admin",
            email=f"{organization.slug}@example.invalid",
            password_hash="",  # noqa: S106 - authentication is not exercised
        )
        for organization in organizations
    ]
    db.add_all(users)
    await db.flush()
    db.add_all(
        [
            EnterpriseConnector(
                organization_id=organization.id,
                connector_type="aws",
                provider="aws",
                name=f"{organization.name} AWS",
                created_by=user.id,
                last_health_check_at=datetime.now(timezone.utc),
            )
            for organization, user in zip(organizations, users, strict=True)
        ]
    )
    await db.flush()
    alpha = list(
        (
            await db.scalars(
                select(EnterpriseConnector).where(
                    EnterpriseConnector.organization_id == organizations[0].id
                )
            )
        ).all()
    )
    assert [connector.name for connector in alpha] == ["Alpha AWS"]
