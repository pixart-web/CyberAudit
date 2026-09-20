from datetime import datetime, timezone

import pytest
from sqlalchemy import select

from cyberaudit.enterprise_models import DetectionRule, Incident, SecurityEvent
from cyberaudit.enterprise_services import (
    DetectionEngine,
    normalize_event,
    validate_incident_transition,
)
from cyberaudit.models import Organization, User


async def _identity(db, suffix: str) -> tuple[Organization, User]:
    organization = Organization(name=f"Tenant {suffix}", slug=f"tenant-{suffix}")
    db.add(organization)
    await db.flush()
    user = User(
        organization_id=organization.id,
        name="SOC Analyst",
        email=f"soc-{suffix}@example.invalid",
        password_hash="",  # noqa: S106 - authentication is not exercised in this unit test
    )
    db.add(user)
    await db.flush()
    return organization, user


def test_event_normalization_is_allowlisted_and_redacts_secrets():
    normalized, digest = normalize_event(
        {
            "action": "login",
            "username": "ana",
            "resource": "token=very-secret",
            "arbitrary": "<script>alert(1)</script>",
        }
    )
    assert normalized["action"] == "login"
    assert normalized["resource"] == "[REDACTED]"
    assert "arbitrary" not in normalized
    assert len(digest) == 64


def test_detection_engine_rejects_code_like_conditions():
    with pytest.raises(ValueError, match="Unsupported detection operator"):
        DetectionEngine.validate_conditions({"count": {"eval": "__import__('os')"}})
    with pytest.raises(ValueError, match="Unsupported detection field"):
        DetectionEngine.validate_conditions({"command": {"equals": "whoami"}})


@pytest.mark.asyncio
async def test_detection_is_deterministic_and_tenant_bound(db):
    organization, user = await _identity(db, "alpha")
    other, _ = await _identity(db, "beta")
    rule = DetectionRule(
        organization_id=organization.id,
        code="AUTH.FAILURES",
        name="Repeated authentication failures",
        severity="high",
        event_types=["authentication.failed"],
        conditions={"count": {"gte": 5}},
        owner_id=user.id,
    )
    other_rule = DetectionRule(
        organization_id=other.id,
        code="OTHER",
        name="Other tenant",
        severity="critical",
        event_types=["authentication.failed"],
        conditions={"count": {"gte": 1}},
        owner_id=(await _identity(db, "gamma"))[1].id,
    )
    event = SecurityEvent(
        organization_id=organization.id,
        source="demo",
        external_id="evt-1",
        event_type="authentication.failed",
        severity="medium",
        occurred_at=datetime.now(timezone.utc),
        summary="Synthetic event",
        normalized={"count": 6},
        content_hash="a" * 64,
    )
    db.add_all([rule, other_rule, event])
    await db.flush()
    alerts = await DetectionEngine().evaluate(db, organization.id, event)
    assert len(alerts) == 1
    assert alerts[0].rule_id == rule.id
    repeated = await DetectionEngine().evaluate(db, organization.id, event)
    assert repeated[0].id == alerts[0].id
    assert repeated[0].occurrence_count == 2


def test_incident_state_machine_rejects_skips():
    validate_incident_transition("open", "triaged")
    with pytest.raises(ValueError, match="Invalid incident transition"):
        validate_incident_transition("open", "closed")


@pytest.mark.asyncio
async def test_incidents_are_isolated_by_organization(db):
    alpha, _ = await _identity(db, "incident-alpha")
    beta, _ = await _identity(db, "incident-beta")
    db.add_all(
        [
            Incident(
                organization_id=alpha.id,
                reference="INC-1",
                title="Alpha",
                simulated=True,
            ),
            Incident(
                organization_id=beta.id,
                reference="INC-1",
                title="Beta",
                simulated=True,
            ),
        ]
    )
    await db.flush()
    rows = list(
        (await db.scalars(select(Incident).where(Incident.organization_id == alpha.id))).all()
    )
    assert [row.title for row in rows] == ["Alpha"]
