from cyberaudit.main import app


def test_update_openapi_contains_expected_routes() -> None:
    routes = set(app.openapi()["paths"])
    assert {"/api/v1/updates/validate"} <= routes
