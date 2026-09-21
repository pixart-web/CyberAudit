"""Closed, non-executing AppSec parsers and decision engines."""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field

MAX_IMPORT_BYTES = 10 * 1024 * 1024
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
SECRET_PATTERNS = {
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "api_token": re.compile(r"\b(?:demo|test)_[A-Za-z0-9_-]{20,}\b"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    "connection_string": re.compile(r"(?i)\b(?:postgres|mysql|mongodb)://[^/\s]+"),
}


class ParsedEndpoint(BaseModel):
    model_config = ConfigDict(extra="forbid")
    method: str
    path_template: str
    normalized_path: str
    operation_id: str | None = None
    summary: str | None = None
    authentication_required: bool = False
    authorization_required: bool = False
    parameters: list[dict[str, Any]] = Field(default_factory=list)
    request_schema: dict[str, Any] = Field(default_factory=dict)
    response_schema: dict[str, Any] = Field(default_factory=dict)
    deprecated: bool = False
    sensitive: bool = False
    data_categories: list[str] = Field(default_factory=list)


class ApiSpecificationPreview(BaseModel):
    title: str
    version: str
    specification_type: str
    base_url: str
    endpoints: list[ParsedEndpoint]
    warnings: list[str] = Field(default_factory=list)


def normalize_api_path(path: str) -> str:
    if not path.startswith("/") or ".." in path or "\\" in path:
        raise ValueError("invalid_api_path")
    return re.sub(r"\{[^{}]+\}", "{id}", re.sub(r"/+", "/", path.rstrip("/") or "/"))


def parse_api_specification(content: bytes) -> ApiSpecificationPreview:
    if len(content) > MAX_IMPORT_BYTES:
        raise ValueError("api_specification_too_large")
    try:
        document = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid_json_specification") from exc
    if not isinstance(document, dict):
        raise ValueError("invalid_specification_root")
    if "$ref" in json.dumps(document) and re.search(
        r'"\$ref"\s*:\s*"(?:https?://|file:|/|\\\\|\.\.)', json.dumps(document)
    ):
        raise ValueError("external_or_unsafe_reference_blocked")
    version = str(document.get("openapi") or document.get("swagger") or "")
    if version.startswith("3.1"):
        kind = "openapi_3_1"
    elif version.startswith("3"):
        kind = "openapi_3"
    elif version.startswith("2"):
        kind = "openapi_2"
    else:
        raise ValueError("unsupported_api_specification")
    raw_info = document.get("info")
    info: dict[str, Any] = raw_info if isinstance(raw_info, dict) else {}
    security_default = bool(document.get("security"))
    endpoints: list[ParsedEndpoint] = []
    for path, operations in list((document.get("paths") or {}).items())[:2000]:
        if not isinstance(operations, dict):
            continue
        normalized = normalize_api_path(str(path))
        for method, operation in operations.items():
            verb = str(method).upper()
            if verb not in {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}:
                continue
            details = operation if isinstance(operation, dict) else {}
            security = details.get("security", document.get("security", []))
            serialized = json.dumps(details).lower()
            endpoints.append(
                ParsedEndpoint(
                    method=verb,
                    path_template=str(path),
                    normalized_path=normalized,
                    operation_id=details.get("operationId"),
                    summary=details.get("summary"),
                    authentication_required=bool(security) or security_default,
                    authorization_required=bool(security),
                    parameters=list(details.get("parameters") or [])[:100],
                    request_schema=dict(details.get("requestBody") or {}),
                    response_schema=dict(details.get("responses") or {}),
                    deprecated=bool(details.get("deprecated")),
                    sensitive=any(
                        term in serialized
                        for term in ("password", "token", "secret", "payment", "health")
                    ),
                    data_categories=[
                        term
                        for term in ("personal", "financial", "health", "authentication")
                        if term in serialized
                    ],
                )
            )
    servers = document.get("servers") or []
    base_url = ""
    if servers and isinstance(servers[0], dict):
        candidate = str(servers[0].get("url") or "")
        parsed = urlsplit(candidate)
        if candidate and (parsed.scheme not in {"http", "https"} or not parsed.hostname):
            raise ValueError("invalid_server_url")
        base_url = candidate
    return ApiSpecificationPreview(
        title=str(info.get("title") or "Imported API")[:180],
        version=str(info.get("version") or "unknown")[:80],
        specification_type=kind,
        base_url=base_url,
        endpoints=endpoints,
        warnings=[] if endpoints else ["no_endpoints_declared"],
    )


class SbomPreview(BaseModel):
    format: str
    specification_version: str
    serial_number: str | None
    components: list[dict[str, Any]]
    dependencies: list[dict[str, Any]]
    warnings: list[str]


def parse_cyclonedx_json(content: bytes) -> SbomPreview:
    if len(content) > MAX_IMPORT_BYTES:
        raise ValueError("sbom_too_large")
    try:
        document = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid_sbom_json") from exc
    if not isinstance(document, dict) or document.get("bomFormat") != "CycloneDX":
        raise ValueError("unsupported_sbom")
    components: list[dict[str, Any]] = []
    for item in list(document.get("components") or [])[:10000]:
        if not isinstance(item, dict) or not item.get("name"):
            continue
        supplier = item.get("supplier")
        supplier_name = supplier.get("name") if isinstance(supplier, dict) else None
        components.append(
            {
                "ref": str(item.get("bom-ref") or item.get("purl") or item["name"])[:1000],
                "component_type": str(item.get("type") or "library")[:60],
                "name": str(item["name"])[:300],
                "group": str(item.get("group") or "")[:300] or None,
                "version": str(item.get("version") or "")[:160] or None,
                "supplier": str(supplier_name or "")[:300] or None,
                "purl": str(item.get("purl") or "")[:1000] or None,
                "cpe": str(item.get("cpe") or "")[:1000] or None,
                "licenses": [
                    str((entry.get("license") or {}).get("id") or "")[:120]
                    for entry in list(item.get("licenses") or [])[:50]
                    if isinstance(entry, dict)
                ],
                "hashes": list(item.get("hashes") or [])[:20],
                "properties": {},
            }
        )
    dependencies = [
        {"ref": str(item.get("ref")), "depends_on": list(item.get("dependsOn") or [])[:1000]}
        for item in list(document.get("dependencies") or [])[:20000]
        if isinstance(item, dict) and item.get("ref")
    ]
    return SbomPreview(
        format="cyclonedx_json",
        specification_version=str(document.get("specVersion") or "unknown")[:40],
        serial_number=str(document.get("serialNumber") or "")[:300] or None,
        components=components,
        dependencies=dependencies,
        warnings=[] if components else ["no_components"],
    )


@dataclass(frozen=True)
class SecretCandidate:
    secret_type: str
    fingerprint: str
    location: str
    length: int
    masked_prefix: str
    confidence: float


def detect_secrets(
    text: str, location: str, maximum_candidates: int = 100
) -> list[SecretCandidate]:
    candidates: list[SecretCandidate] = []
    for kind, pattern in SECRET_PATTERNS.items():
        for match in pattern.finditer(text):
            value = match.group(0)
            candidates.append(
                SecretCandidate(
                    secret_type=kind,
                    fingerprint=hashlib.sha256(value.encode()).hexdigest(),
                    location=location[:1000],
                    length=len(value),
                    masked_prefix=(value[:3] + "…") if kind != "private_key" else "KEY…",
                    confidence=0.9,
                )
            )
            if len(candidates) >= maximum_candidates:
                return candidates
    return candidates


def parse_dependency_manifest(filename: str, content: bytes) -> list[dict[str, str]]:
    if len(content) > MAX_IMPORT_BYTES:
        raise ValueError("dependency_manifest_too_large")
    name = filename.lower()
    text = content.decode("utf-8", errors="strict")
    dependencies: list[dict[str, str]] = []
    if name == "requirements.txt":
        for line in text.splitlines()[:10000]:
            value = line.strip()
            if not value or value.startswith("#"):
                continue
            match = re.fullmatch(r"([A-Za-z0-9_.-]+)==([A-Za-z0-9_.+-]+)", value)
            if not match:
                raise ValueError("unlocked_or_unsafe_requirement")
            dependencies.append(
                {"ecosystem": "pypi", "name": match.group(1).lower(), "version": match.group(2)}
            )
    elif name in {"package-lock.json", "npm-shrinkwrap.json"}:
        document = json.loads(text)
        for package_path, item in list((document.get("packages") or {}).items())[:10000]:
            if package_path and isinstance(item, dict) and item.get("version"):
                package = package_path.rsplit("node_modules/", 1)[-1]
                dependencies.append(
                    {"ecosystem": "npm", "name": package, "version": str(item["version"])}
                )
    else:
        raise ValueError("unsupported_dependency_manifest")
    return dependencies


class AppSecRiskContext(BaseModel):
    public_exposure: bool = False
    authentication_required: bool = True
    data_sensitivity: float = Field(default=40, ge=0, le=100)
    application_criticality: float = Field(default=50, ge=0, le=100)
    technical_severity: float = Field(default=50, ge=0, le=100)
    known_exploited: bool = False
    runtime_presence: bool = False
    production_deployment: bool = False
    direct_dependency: bool = True
    compensating_controls: int = Field(default=0, ge=0, le=10)
    confidence: float = Field(default=0.5, ge=0, le=1)


def calculate_appsec_risk(context: AppSecRiskContext) -> dict[str, Any]:
    exposure = 80 if context.public_exposure else 25
    auth = 10 if context.authentication_required else 70
    score = (
        context.technical_severity * 0.28
        + exposure * 0.17
        + auth * 0.1
        + context.data_sensitivity * 0.12
        + context.application_criticality * 0.15
        + (100 if context.known_exploited else 20) * 0.08
        + (85 if context.runtime_presence else 30) * 0.05
        + (80 if context.production_deployment else 30) * 0.05
    )
    score = max(0, min(100, score - context.compensating_controls * 4))
    return {
        "score": round(score, 2),
        "confidence": round(context.confidence, 2),
        "level": (
            "critical"
            if score >= 80
            else "high" if score >= 60 else "medium" if score >= 35 else "low"
        ),
        "formula_version": "appsec-risk-1.0",
        "explanation": (
            f"Risco contextual {'público' if context.public_exposure else 'interno'}, "
            f"{'com' if context.authentication_required else 'sem'} autenticação declarada, "
            f"{'presença' if context.runtime_presence else 'presença não confirmada'} em runtime."
        ),
    }


def evaluate_security_gate(policy: dict[str, Any], state: dict[str, Any]) -> tuple[str, list[str]]:
    reasons: list[str] = []
    if state.get("appsec_score", 0) < policy.get("minimum_appsec_score", 0):
        reasons.append("appsec_score_below_minimum")
    if state.get("critical_findings", 0) > policy.get("maximum_critical_findings", 0):
        reasons.append("critical_findings_limit_exceeded")
    if state.get("high_findings", 0) > policy.get("maximum_high_findings", 0):
        reasons.append("high_findings_limit_exceeded")
    if policy.get("block_known_exploited") and state.get("known_exploited", 0):
        reasons.append("known_exploited_dependency")
    if policy.get("block_confirmed_secrets") and state.get("confirmed_secrets", 0):
        reasons.append("confirmed_secret")
    if policy.get("block_unsigned_artifacts") and not state.get("artifact_signed"):
        reasons.append("artifact_signature_missing")
    for required, key in [
        ("require_sbom", "has_sbom"),
        ("require_sast", "has_sast"),
        ("require_sca", "has_sca"),
        ("require_iac_scan", "has_iac_scan"),
        ("require_container_scan", "has_container_scan"),
    ]:
        if policy.get(required) and not state.get(key):
            reasons.append(f"{key}_missing")
    return ("failed" if reasons else "passed", reasons)


def entropy(value: str) -> float:
    if not value:
        return 0
    return -sum(
        (count / len(value)) * math.log2(count / len(value))
        for count in {character: value.count(character) for character in set(value)}.values()
    )
