from cyberaudit.main import app


def test_phase5_openapi_contains_core_routes() -> None:
    routes = set(app.openapi()["paths"])
    expected = {
        "/api/v1/applications",
        "/api/v1/applications/{application_id}",
        "/api/v1/apis",
        "/api/v1/apis/{api_id}/endpoints",
        "/api/v1/api-specifications",
        "/api/v1/repositories",
        "/api/v1/sboms",
        "/api/v1/sboms/{sbom_id}/components",
        "/api/v1/releases",
        "/api/v1/security-gates",
        "/api/v1/security-gates/{gate_id}/evaluate",
        "/api/v1/appsec-exceptions",
        "/api/v1/appsec-remediations",
        "/api/v1/appsec/command-center",
        "/api/v1/appsec/risk",
        "/api/v1/appsec/coverage",
        "/api/v1/appsec/trends",
    }
    assert expected <= routes
