from cyberaudit.main import app


def test_ai_runtime_openapi_contains_expected_routes() -> None:
    routes = set(app.openapi()["paths"])
    assert {
        "/api/v1/ai-runtime/hardware",
        "/api/v1/ai-runtime/health",
        "/api/v1/ai-runtime/models",
        "/api/v1/ai-runtime/models/{manifest_id}/install-status",
        "/api/v1/ai-runtime/capabilities/{capability}",
    } <= routes
