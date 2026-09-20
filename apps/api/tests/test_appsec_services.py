import json

import pytest

from cyberaudit.appsec_services import (
    MAX_IMPORT_BYTES,
    AppSecRiskContext,
    calculate_appsec_risk,
    detect_secrets,
    evaluate_security_gate,
    normalize_api_path,
    parse_api_specification,
    parse_cyclonedx_json,
    parse_dependency_manifest,
)


def test_openapi_import_is_offline_bounded_and_normalized() -> None:
    document = {
        "openapi": "3.1.0",
        "info": {"title": "Synthetic API", "version": "1"},
        "servers": [{"url": "https://api.example.invalid"}],
        "paths": {
            "/users/{userId}": {
                "get": {
                    "operationId": "getUser",
                    "security": [{"demo": []}],
                    "summary": "Synthetic personal record",
                }
            }
        },
    }
    result = parse_api_specification(json.dumps(document).encode())
    assert result.specification_type == "openapi_3_1"
    assert result.endpoints[0].normalized_path == "/users/{id}"
    assert result.endpoints[0].authentication_required is True
    assert result.endpoints[0].method == "GET"


@pytest.mark.parametrize(
    "reference",
    [
        "https://example.invalid/schema.json",
        "file:///etc/passwd",
        "../../private.json",
        "/absolute/schema.json",
    ],
)
def test_openapi_external_references_are_blocked(reference: str) -> None:
    document = {
        "openapi": "3.0.0",
        "info": {"title": "Blocked", "version": "1"},
        "paths": {"/demo": {"get": {"responses": {"200": {"$ref": reference}}}}},
    }
    with pytest.raises(ValueError, match="external_or_unsafe_reference_blocked"):
        parse_api_specification(json.dumps(document).encode())


def test_openapi_size_and_path_traversal_are_blocked() -> None:
    with pytest.raises(ValueError, match="too_large"):
        parse_api_specification(b"x" * (MAX_IMPORT_BYTES + 1))
    with pytest.raises(ValueError, match="invalid_api_path"):
        normalize_api_path("/../admin")


def test_cyclonedx_parser_accepts_components_without_installing_them() -> None:
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": "urn:uuid:demo",
        "components": [
            {
                "bom-ref": "pkg:pypi/demo@1.0",
                "type": "library",
                "name": "demo",
                "version": "1.0",
                "purl": "pkg:pypi/demo@1.0",
            }
        ],
        "dependencies": [{"ref": "pkg:pypi/demo@1.0", "dependsOn": []}],
    }
    result = parse_cyclonedx_json(json.dumps(document).encode())
    assert result.format == "cyclonedx_json"
    assert result.components[0]["name"] == "demo"
    assert result.dependencies[0]["depends_on"] == []


def test_only_cyclonedx_json_is_accepted() -> None:
    with pytest.raises(ValueError, match="unsupported_sbom"):
        parse_cyclonedx_json(b'{"bomFormat":"SPDX"}')
    with pytest.raises(ValueError, match="invalid_sbom_json"):
        parse_cyclonedx_json(b"<xml />")


def test_secret_detection_never_returns_the_raw_value() -> None:
    raw = "demo_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    candidates = detect_secrets(f"DEMO={raw}", "fixture.env:1")
    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.fingerprint
    assert candidate.masked_prefix.endswith("…")
    assert raw not in repr(candidate)


def test_dependency_parser_requires_locked_versions() -> None:
    assert parse_dependency_manifest("requirements.txt", b"fastapi==0.115.0\n") == [
        {"ecosystem": "pypi", "name": "fastapi", "version": "0.115.0"}
    ]
    with pytest.raises(ValueError, match="unlocked_or_unsafe_requirement"):
        parse_dependency_manifest("requirements.txt", b"fastapi>=0.100\n")
    with pytest.raises(ValueError, match="unsupported_dependency_manifest"):
        parse_dependency_manifest("setup.py", b"print('never execute')")


def test_risk_formula_is_explainable_and_bounded() -> None:
    result = calculate_appsec_risk(
        AppSecRiskContext(
            public_exposure=True,
            authentication_required=False,
            technical_severity=100,
            application_criticality=100,
            data_sensitivity=100,
            known_exploited=True,
            runtime_presence=True,
            production_deployment=True,
            confidence=0.9,
        )
    )
    assert 0 <= result["score"] <= 100
    assert result["level"] == "critical"
    assert result["formula_version"] == "appsec-risk-1.0"
    assert result["explanation"]


def test_security_gate_is_deterministic_and_fail_closed() -> None:
    policy = {
        "minimum_appsec_score": 75,
        "maximum_critical_findings": 0,
        "maximum_high_findings": 0,
        "block_confirmed_secrets": True,
        "block_unsigned_artifacts": True,
        "require_sbom": True,
        "require_sca": True,
    }
    state = {
        "appsec_score": 60,
        "critical_findings": 1,
        "high_findings": 0,
        "confirmed_secrets": 1,
        "artifact_signed": False,
        "has_sbom": False,
        "has_sca": False,
    }
    decision, reasons = evaluate_security_gate(policy, state)
    assert decision == "failed"
    assert {
        "appsec_score_below_minimum",
        "critical_findings_limit_exceeded",
        "confirmed_secret",
        "artifact_signature_missing",
        "has_sbom_missing",
        "has_sca_missing",
    }.issubset(reasons)
