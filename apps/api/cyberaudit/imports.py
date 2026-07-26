import csv
import io
import json
from typing import Any, Literal, cast

from defusedxml import ElementTree as ET
from pydantic import BaseModel, ConfigDict, Field

from cyberaudit.evidence import EvidenceSanitizer
from cyberaudit.models import Criticality

MAX_IMPORT_BYTES = 5 * 1024 * 1024
ALLOWED_IMPORT_EXTENSIONS = {".json", ".csv", ".sarif", ".xml"}
ALLOWED_IMPORT_MIME_TYPES = {
    "application/json",
    "text/csv",
    "application/sarif+json",
    "application/xml",
    "text/xml",
}


class ImportedFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: str = Field(min_length=1, max_length=240)
    description: str = Field(default="", max_length=20_000)
    category: str = Field(default="imported", max_length=120)
    severity: Criticality = Criticality.LOW
    confidence: Literal["low", "medium", "high"] = "medium"
    affected_component: str = Field(default="unknown", max_length=500)
    source_identifier: str = Field(min_length=1, max_length=500)
    observed_value: str | None = Field(default=None, max_length=10_000)
    expected_value: str | None = Field(default=None, max_length=10_000)
    remediation: str = Field(default="Rever e validar o resultado importado.", max_length=20_000)
    references: list[str] = Field(default_factory=list, max_length=30)


class ImportPreview(BaseModel):
    format: str
    finding_count: int
    findings: list[ImportedFinding]
    warnings: list[str] = Field(default_factory=list)


def detect_import_format(filename: str, mime_type: str) -> str:
    lower = filename.lower()
    if lower.endswith(".sarif"):
        return "sarif"
    if lower.endswith(".csv"):
        return "cyberaudit_csv"
    if lower.endswith(".xml"):
        return "xml"
    if lower.endswith(".json") and mime_type in {"application/json", "application/sarif+json"}:
        return "json"
    raise ValueError("unsupported_import_format")


def parse_import(content: bytes, format_hint: str) -> ImportPreview:
    if len(content) > MAX_IMPORT_BYTES:
        raise ValueError("import_too_large")
    if format_hint == "cyberaudit_csv":
        return _parse_csv(content)
    if format_hint == "xml":
        return _parse_xml(content)
    if format_hint in {"json", "sarif"}:
        try:
            payload = json.loads(content.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("invalid_json_import") from exc
        if _looks_like_sarif(payload):
            return _parse_sarif(payload)
        if _looks_like_cyclonedx(payload):
            return _parse_cyclonedx(payload)
        return _parse_cyberaudit_json(payload)
    raise ValueError("unsupported_import_format")


def _parse_cyberaudit_json(payload: Any) -> ImportPreview:
    if not isinstance(payload, dict) or not isinstance(payload.get("findings"), list):
        raise ValueError("invalid_cyberaudit_json")
    findings = [_normalize_mapping(item, index) for index, item in enumerate(payload["findings"])]
    return ImportPreview(
        format="cyberaudit_json", finding_count=len(findings), findings=findings[:1000]
    )


def _parse_csv(content: bytes) -> ImportPreview:
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError("invalid_csv_encoding") from exc
    reader = csv.DictReader(io.StringIO(text))
    required = {"title", "severity"}
    if not reader.fieldnames or not required.issubset(set(reader.fieldnames)):
        raise ValueError("invalid_csv_columns")
    findings = [_normalize_mapping(row, index) for index, row in enumerate(reader)]
    return ImportPreview(
        format="cyberaudit_csv", finding_count=len(findings), findings=findings[:1000]
    )


def _parse_sarif(payload: dict[str, Any]) -> ImportPreview:
    findings: list[ImportedFinding] = []
    for run_index, run in enumerate(payload.get("runs", [])):
        for result_index, result in enumerate(run.get("results", [])):
            rule_id = str(result.get("ruleId") or f"sarif-{run_index}-{result_index}")
            message = result.get("message", {})
            location = ""
            locations = result.get("locations") or []
            if locations:
                location = (
                    locations[0]
                    .get("physicalLocation", {})
                    .get("artifactLocation", {})
                    .get("uri", "")
                )
            findings.append(
                _normalize_mapping(
                    {
                        "title": rule_id,
                        "description": message.get("text", ""),
                        "severity": _sarif_level(result.get("level")),
                        "category": "sarif",
                        "affected_component": location or "imported artifact",
                        "source_identifier": rule_id,
                    },
                    result_index,
                )
            )
    return ImportPreview(format="sarif", finding_count=len(findings), findings=findings[:1000])


def _parse_cyclonedx(payload: dict[str, Any]) -> ImportPreview:
    findings: list[ImportedFinding] = []
    for index, vulnerability in enumerate(payload.get("vulnerabilities", [])):
        identifier = str(vulnerability.get("id") or f"cyclonedx-{index}")
        ratings = vulnerability.get("ratings") or []
        severity = ratings[0].get("severity") if ratings else "low"
        findings.append(
            _normalize_mapping(
                {
                    "title": identifier,
                    "description": vulnerability.get("description", ""),
                    "severity": severity,
                    "category": "dependency",
                    "affected_component": _cyclonedx_component(vulnerability),
                    "source_identifier": identifier,
                    "recommendation": vulnerability.get("recommendation", ""),
                },
                index,
            )
        )
    return ImportPreview(format="cyclonedx", finding_count=len(findings), findings=findings[:1000])


def _parse_xml(content: bytes) -> ImportPreview:
    upper = content[:4096].upper()
    if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
        raise ValueError("xml_external_entities_blocked")
    try:
        root = ET.fromstring(content)
    except ET.ParseError as exc:
        raise ValueError("invalid_xml_import") from exc
    if len(list(root.iter())) > 10_000:
        raise ValueError("xml_element_limit_exceeded")
    findings = []
    for index, node in enumerate(root.findall(".//finding")):
        mapping = {child.tag: child.text or "" for child in list(node)}
        findings.append(_normalize_mapping(mapping, index))
    return ImportPreview(
        format="cyberaudit_xml", finding_count=len(findings), findings=findings[:1000]
    )


def _normalize_mapping(value: Any, index: int) -> ImportedFinding:
    if not isinstance(value, dict):
        raise ValueError("invalid_import_finding")
    sanitizer = EvidenceSanitizer(redact_emails=True)

    def safe(key: str, default: str = "") -> str:
        return sanitizer.sanitize_text(str(value.get(key) or default)).content

    title = safe("title", f"Imported finding {index + 1}")
    source = safe("source_identifier", safe("id", f"import-{index}"))
    return ImportedFinding(
        title=title,
        description=safe("description"),
        category=safe("category", "imported"),
        severity=_severity(value.get("severity")),
        confidence=_confidence(safe("confidence", "medium")),
        affected_component=safe("affected_component", safe("component", "unknown")),
        source_identifier=source,
        observed_value=safe("observed_value") or None,
        expected_value=safe("expected_value") or None,
        remediation=safe("remediation", safe("recommendation", "Rever o resultado importado.")),
        references=[str(item)[:500] for item in value.get("references", [])][:30],
    )


def _severity(value: Any) -> Criticality:
    normalized = str(value or "low").lower()
    aliases = {
        "info": Criticality.LOW,
        "informational": Criticality.LOW,
        "warning": Criticality.MEDIUM,
        "error": Criticality.HIGH,
    }
    if normalized in aliases:
        return aliases[normalized]
    try:
        return Criticality(normalized)
    except ValueError:
        return Criticality.LOW


def _confidence(value: str) -> Literal["low", "medium", "high"]:
    normalized = value.lower()
    if normalized in {"low", "medium", "high"}:
        return cast(Literal["low", "medium", "high"], normalized)
    return "medium"


def _sarif_level(value: Any) -> str:
    return {"none": "low", "note": "low", "warning": "medium", "error": "high"}.get(
        str(value or "warning").lower(), "low"
    )


def _cyclonedx_component(value: dict[str, Any]) -> str:
    affects = value.get("affects") or []
    return str(affects[0].get("ref")) if affects else "imported component"


def _looks_like_sarif(payload: Any) -> bool:
    return (
        isinstance(payload, dict)
        and "runs" in payload
        and str(payload.get("version", "")).startswith("2.")
    )


def _looks_like_cyclonedx(payload: Any) -> bool:
    return isinstance(payload, dict) and payload.get("bomFormat") == "CycloneDX"
