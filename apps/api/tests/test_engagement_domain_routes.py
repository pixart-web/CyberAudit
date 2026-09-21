from cyberaudit.main import app


def test_engagement_domain_openapi_contains_expected_routes() -> None:
    routes = set(app.openapi()["paths"])
    assert {
        "/api/v1/engagements/{engagement_id}/notes",
        "/api/v1/engagements/{engagement_id}/timeline",
        "/api/v1/engagements/{engagement_id}/reports",
        "/api/v1/reports/{report_id}",
    } <= routes
