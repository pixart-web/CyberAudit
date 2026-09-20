from cyberaudit.main import app


def test_agent_openapi_contains_expected_routes() -> None:
    routes = set(app.openapi()["paths"])
    assert {
        "/api/v1/agents",
        "/api/v1/agents/{agent_code}/ask",
        "/api/v1/agents/{agent_code}/tools/{tool_name}",
    } <= routes
