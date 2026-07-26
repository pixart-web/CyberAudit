import json

import pytest

from cyberaudit.evidence import EvidenceSanitizer
from cyberaudit.imports import detect_import_format, parse_import


def test_sanitizes_authorization_cookie_and_tokens():
    sanitizer = EvidenceSanitizer()
    result = sanitizer.sanitize_headers(
        {
            "authorization": ["Bearer secret-token"],
            "set-cookie": ["session=abc123; Secure; HttpOnly; SameSite=Lax"],
            "x-api-key": ["token=abcdef0123456789abcdef0123456789"],
        }
    )
    assert "abc123" not in result.content
    assert "secret-token" not in result.content
    assert "session=[REDACTED]" in result.content
    assert result.redacted is True


def test_sanitizes_sensitive_query_parameters():
    value = EvidenceSanitizer().sanitize_url(
        "https://example.test/path?token=secret&view=summary#fragment"
    )
    assert "secret" not in value
    assert "token=%5BREDACTED%5D" in value
    assert "view=summary" in value
    assert "#" not in value


def test_imports_cyberaudit_json_and_sanitizes_content():
    content = json.dumps(
        {
            "findings": [
                {
                    "title": "Observed issue",
                    "severity": "high",
                    "description": "token=very-secret",
                    "affected_component": "service-a",
                    "source_identifier": "test.rule",
                }
            ]
        }
    ).encode()
    preview = parse_import(content, "json")
    assert preview.format == "cyberaudit_json"
    assert preview.finding_count == 1
    assert preview.findings[0].severity.value == "high"
    assert "very-secret" not in preview.findings[0].description


def test_imports_csv():
    preview = parse_import(
        b"title,severity,affected_component,source_identifier\nMissing header,low,web,csv.rule\n",
        "cyberaudit_csv",
    )
    assert preview.finding_count == 1
    assert preview.findings[0].source_identifier == "csv.rule"


def test_imports_sarif():
    payload = {
        "version": "2.1.0",
        "runs": [
            {
                "results": [
                    {
                        "ruleId": "SAFE001",
                        "level": "warning",
                        "message": {"text": "Controlled result"},
                    }
                ]
            }
        ],
    }
    preview = parse_import(json.dumps(payload).encode(), "sarif")
    assert preview.format == "sarif"
    assert preview.findings[0].severity.value == "medium"


def test_imports_cyclonedx():
    payload = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "vulnerabilities": [
            {
                "id": "DEMO-1",
                "description": "Imported only",
                "ratings": [{"severity": "low"}],
                "affects": [{"ref": "pkg:generic/demo@1"}],
            }
        ],
    }
    preview = parse_import(json.dumps(payload).encode(), "json")
    assert preview.format == "cyclonedx"
    assert preview.findings[0].affected_component == "pkg:generic/demo@1"


def test_safe_xml_import():
    preview = parse_import(
        b"<cyberaudit><finding><title>XML finding</title><severity>low</severity>"
        b"<source_identifier>xml.rule</source_identifier></finding></cyberaudit>",
        "xml",
    )
    assert preview.finding_count == 1


def test_xml_entities_are_rejected():
    with pytest.raises(ValueError, match="xml_external_entities_blocked"):
        parse_import(
            b'<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]>'
            b"<cyberaudit><finding><title>&e;</title></finding></cyberaudit>",
            "xml",
        )


def test_invalid_extension_is_rejected():
    with pytest.raises(ValueError, match="unsupported_import_format"):
        detect_import_format("results.html", "text/html")
