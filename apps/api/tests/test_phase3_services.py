import pytest
from fastapi import HTTPException

from cyberaudit.correlation import FindingCorrelationService
from cyberaudit.models import Criticality, Evidence, Finding
from cyberaudit.network_security import build_network_policy
from cyberaudit.phase3_api import _tenant_evidence


async def test_evidence_tenant_isolation(db):
    evidence = Evidence(
        organization_id="org-a",
        engagement_id="eng-a",
        job_id="job-a",
        evidence_type="structured_data",
        title="Tenant A evidence",
        content_hash="a" * 64,
        size_bytes=0,
        collected_by_adapter="cyberaudit.asset_inventory",
    )
    db.add(evidence)
    await db.commit()
    assert (await _tenant_evidence(db, evidence.id, "org-a")).id == evidence.id
    with pytest.raises(HTTPException) as exc:
        await _tenant_evidence(db, evidence.id, "org-b")
    assert exc.value.status_code == 404


async def test_correlation_raises_confidence_but_not_severity(db):
    common = {
        "organization_id": "org-a",
        "engagement_id": "eng-a",
        "job_id": "job-a",
        "title": "Observed configuration",
        "description": "Controlled",
        "category": "configuration",
        "technical_severity": Criticality.LOW,
        "confidence": "medium",
        "affected_component": "service-a",
        "technical_impact": "Limited",
        "business_impact": "Context dependent",
        "remediation_summary": "Review",
        "validation_steps": ["Retest"],
        "observed_value": "missing",
        "location": "/",
    }
    first = Finding(
        **common,
        source_adapter="cyberaudit.http_security_headers",
        fingerprint="a" * 64,
    )
    second = Finding(
        **(common | {"job_id": "job-b"}),
        source_adapter="cyberaudit.public_configuration",
        fingerprint="b" * 64,
    )
    db.add_all([first, second])
    await db.commit()
    result = await FindingCorrelationService().correlate_engagement(
        db, organization_id="org-a", engagement_id="eng-a"
    )
    assert result == {"correlated": 2, "confidence_raised": 2}
    assert first.confidence == "high"
    assert first.technical_severity == Criticality.LOW


def test_backend_network_policy_uses_category_caps():
    policy = build_network_policy(
        category="http_security_headers",
        profile_timeout=9999,
        laboratory_mode=True,
    )
    assert policy.maximum_requests == 4
    assert policy.maximum_response_bytes == 131_072
    assert policy.total_timeout == 120
    assert policy.allow_public_addresses is False
    assert policy.allow_private_addresses is True
