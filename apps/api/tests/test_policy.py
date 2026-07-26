from datetime import date, datetime, time, timezone
from types import SimpleNamespace

import pytest

from cyberaudit.models import EngagementMode, EngagementStatus, Intensity, TargetType
from cyberaudit.policy import (
    PolicyContext,
    ScopePolicyEngine,
    is_private_destination,
    normalized_target,
    target_matches,
)
from cyberaudit.schemas import PolicyRequest


def obj(**kwargs):
    defaults = {"deleted_at": None}
    return SimpleNamespace(**(defaults | kwargs))


def request(**overrides):
    data = {
        "organization_id": "org-1",
        "engagement_id": "eng-1",
        "operator_id": "user-1",
        "target_type": TargetType.IP,
        "target_value": "10.20.0.10",
        "technique": "asset-discovery",
        "requested_intensity": Intensity.NORMAL,
        "requested_at": datetime(2026, 7, 23, 10, tzinfo=timezone.utc),
    }
    return PolicyRequest(**(data | overrides))


def context(**overrides):
    scope = obj(
        id="scope-1",
        status="active",
        emergency_stop_enabled=False,
        timezone="UTC",
        allowed_start_time=time(8),
        allowed_end_time=time(20),
        maximum_intensity=Intensity.NORMAL,
        allowed_techniques=["asset-discovery"],
    )
    target = obj(
        scope_id="scope-1",
        allowed=True,
        target_type=TargetType.CIDR,
        normalized_value="10.20.0.0/24",
        include_subdomains=False,
    )
    data = {
        "organization": obj(id="org-1", status="active"),
        "operator": obj(id="user-1", status="active", organization_id="org-1"),
        "engagement": obj(
            id="eng-1",
            status=EngagementStatus.ACTIVE,
            organization_id="org-1",
            mode=EngagementMode.CLIENT,
        ),
        "authorizations": [
            obj(status="valid", valid_from=date(2026, 1, 1), valid_until=date(2026, 12, 31))
        ],
        "scopes": [scope],
        "targets": [target],
    }
    return PolicyContext(**(data | overrides))


def test_ip_inside_cidr_allowed():
    result = ScopePolicyEngine().evaluate_context(request(), context())
    assert result.decision == "allowed"


def test_ip_outside_cidr_denied():
    result = ScopePolicyEngine().evaluate_context(request(target_value="10.21.0.1"), context())
    assert "target_out_of_scope" in result.reasons


def test_expired_authorization_denied():
    ctx = context(
        authorizations=[
            obj(status="valid", valid_from=date(2025, 1, 1), valid_until=date(2025, 12, 31))
        ]
    )
    assert (
        "authorization_missing_or_expired"
        in ScopePolicyEngine().evaluate_context(request(), ctx).reasons
    )


@pytest.mark.parametrize(
    "value,expected",
    [
        ("127.0.0.1", True),
        ("10.0.0.1", True),
        ("8.8.8.8", False),
        ("example.com", False),
        ("localhost", True),
    ],
)
def test_laboratory_destinations(value, expected):
    target_type = TargetType.IP if value[0].isdigit() else TargetType.DOMAIN
    assert is_private_destination(target_type, value) is expected


def test_emergency_stop_denied():
    ctx = context()
    ctx.scopes[0].emergency_stop_enabled = True
    assert "emergency_stop_enabled" in ScopePolicyEngine().evaluate_context(request(), ctx).reasons


def test_intensity_requires_approval_when_permitted():
    ctx = context()
    ctx.scopes[0].maximum_intensity = Intensity.ELEVATED
    result = ScopePolicyEngine().evaluate_context(
        request(requested_intensity=Intensity.ELEVATED), ctx
    )
    assert result.decision == "requires_approval"


def test_subdomain_matching():
    target = obj(
        allowed=True,
        target_type=TargetType.DOMAIN,
        normalized_value="internal.test",
        include_subdomains=True,
    )
    assert target_matches(TargetType.DOMAIN, "api.internal.test", target)


def test_wrong_tenant_denied():
    ctx = context()
    ctx.operator.organization_id = "org-2"
    assert (
        "operator_wrong_organization"
        in ScopePolicyEngine().evaluate_context(request(), ctx).reasons
    )


def test_url_normalization_preserves_non_default_port():
    assert normalized_target(TargetType.URL, "HTTP://Localhost:8080") == "http://localhost:8080/"


def test_laboratory_local_url_is_private():
    assert is_private_destination(TargetType.URL, "http://localhost:8080/") is True
