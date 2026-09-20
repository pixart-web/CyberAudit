import pytest
from pydantic import ValidationError

from cyberaudit.enterprise_api import DetectionRulePayload, EventPayload
from cyberaudit.main import app


def test_enterprise_openapi_contains_core_routes() -> None:
    routes = set(app.openapi()["paths"])
    expected = {
        "/api/v1/soc/dashboard",
        "/api/v1/security-events",
        "/api/v1/detections/rules",
        "/api/v1/detections/alerts",
        "/api/v1/incidents",
        "/api/v1/incidents/{incident_id}/transition",
        "/api/v1/cases",
        "/api/v1/iocs",
        "/api/v1/threat-intelligence/feeds",
        "/api/v1/hunts",
        "/api/v1/playbooks",
        "/api/v1/security-data-lake",
        "/api/v1/purple-team/exercises",
        "/api/v1/attack-graph/v3",
        "/api/v1/risk/v3",
        "/api/v1/grc/dashboard",
        "/api/v1/grc/frameworks",
        "/api/v1/grc/controls",
        "/api/v1/grc/control-mappings",
        "/api/v1/grc/control-assessments",
        "/api/v1/grc/risks",
        "/api/v1/grc/policies",
        "/api/v1/grc/evidence-links",
        "/api/v1/grc/exceptions",
        "/api/v1/knowledge-graph",
        "/api/v1/knowledge-nodes",
        "/api/v1/ai/services",
        "/api/v1/ai/assist",
        "/api/v1/ai/requests",
    }
    assert expected <= routes


def test_enterprise_payloads_reject_extra_fields() -> None:
    with pytest.raises(ValidationError):
        EventPayload.model_validate(
            {
                "source": "demo",
                "external_id": "1",
                "event_type": "demo.event",
                "occurred_at": "2026-07-29T10:00:00Z",
                "summary": "Synthetic",
                "data": {},
                "command": "whoami",
            }
        )
    with pytest.raises(ValidationError):
        DetectionRulePayload.model_validate(
            {
                "code": "DEMO",
                "name": "Demo rule",
                "conditions": {},
                "python": "import os",
            }
        )
