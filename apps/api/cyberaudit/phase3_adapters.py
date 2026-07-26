from __future__ import annotations

import asyncio
import json
import ssl
from abc import abstractmethod
from datetime import datetime, timezone
from typing import Any, ClassVar, Literal
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from pydantic import BaseModel, ConfigDict, Field

from cyberaudit.adapters import (
    AdapterExecutionContext,
    AdapterExecutionResult,
    AdapterExecutionSummary,
    AdapterMetadata,
    AdapterRequest,
    AdapterWarning,
    ExecutionEstimate,
    HealthCheckResult,
    NormalizedEvidence,
    NormalizedFinding,
    NormalizedTarget,
    ParsedAdapterOutput,
    ToolAdapter,
    ValidationResult,
)
from cyberaudit.evidence import EvidenceSanitizer
from cyberaudit.models import Criticality, Intensity, TargetType
from cyberaudit.network_security import (
    NetworkExecutionPolicy,
    NetworkPolicyViolation,
    SecureDnsResolver,
    SecureHttpClient,
    first_header,
    normalize_hostname,
    validate_url,
)


class AssetInventoryConfiguration(BaseModel):
    model_config = ConfigDict(extra="forbid")
    sources: list[Literal["platform", "dns", "http", "tls", "manual", "future_cmdb"]] = Field(
        default_factory=lambda: _default_inventory_sources(), min_length=1, max_length=4
    )


class DnsAssessmentConfiguration(BaseModel):
    model_config = ConfigDict(extra="forbid")
    record_types: list[Literal["A", "AAAA", "CNAME", "MX", "NS", "TXT", "CAA", "SOA"]] = Field(
        default_factory=lambda: _default_dns_record_types(),
        min_length=1,
        max_length=8,
    )
    check_dnssec: bool = True


class TlsAssessmentConfiguration(BaseModel):
    model_config = ConfigDict(extra="forbid")
    port: Literal[443, 8443] = 443
    sni: str | None = Field(default=None, max_length=253)
    expiry_warning_days: int = Field(default=30, ge=1, le=90)


class HttpAssessmentConfiguration(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scheme: Literal["https", "http"] = "https"
    path: Literal["/"] = "/"
    fallback_get: bool = True


class TechnologyConfiguration(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scheme: Literal["https", "http"] = "https"
    path: Literal["/"] = "/"
    inspect_html: bool = True


class PublicConfigurationConfiguration(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scheme: Literal["https", "http"] = "https"
    endpoint: Literal[
        "/robots.txt",
        "/.well-known/security.txt",
        "/sitemap.xml",
        "/manifest.json",
    ] = "/.well-known/security.txt"


class ExternalImportAdapterConfiguration(BaseModel):
    model_config = ConfigDict(extra="forbid")
    import_id: str = Field(min_length=36, max_length=36)


def _real_summary(
    message: str, status: Literal["success", "warning"] = "success"
) -> AdapterExecutionSummary:
    return AdapterExecutionSummary(status=status, message=message, simulated=False)


def _evidence(kind: str, summary: str, payload: Any) -> NormalizedEvidence:
    content = (
        payload
        if isinstance(payload, str)
        else json.dumps(payload, ensure_ascii=False, sort_keys=True)
    )
    sanitized = EvidenceSanitizer().sanitize_text(content)
    return NormalizedEvidence(
        kind=kind,
        summary=summary,
        content=sanitized.content,
        simulated=False,
        metadata={"redacted": sanitized.redacted},
    )


class JsonResultAdapter(ToolAdapter):
    configuration_model: ClassVar[type[BaseModel]]
    target_types: ClassVar[list[TargetType]]
    adapter_code: ClassVar[str]
    adapter_name: ClassVar[str]
    category: ClassVar[str]
    description: ClassVar[str]
    requires_network: ClassVar[bool] = True
    default_timeout: ClassVar[int] = 20

    def __init__(self) -> None:
        self._cancelled: set[str] = set()

    def metadata(self) -> AdapterMetadata:
        return AdapterMetadata(
            code=self.adapter_code,
            name=self.adapter_name,
            version="1.0.0",
            category=self.category,
            description=self.description,
            supported_target_types=self.target_types,
            supported_intensities=[Intensity.PASSIVE, Intensity.LOW],
            requires_network=self.requires_network,
            requires_approval=False,
            default_timeout=self.default_timeout,
            configuration_schema=self.configuration_model.model_json_schema(),
        )

    async def validate_configuration(self, configuration: dict[str, Any]) -> ValidationResult:
        try:
            self.configuration_model.model_validate(configuration)
        except ValueError as exc:
            return ValidationResult(valid=False, errors=[str(exc)])
        return ValidationResult(valid=True)

    async def validate_target(self, target: NormalizedTarget) -> ValidationResult:
        if target.target_type not in self.target_types:
            return ValidationResult(valid=False, errors=["unsupported_target_type"])
        try:
            if target.target_type == TargetType.URL:
                url = validate_url(
                    target.value,
                    NetworkExecutionPolicy(allowed_ports=(80, 443, 8080, 8443)),
                )
                normalize_hostname(url.parsed.hostname or "")
            elif target.target_type in {TargetType.DOMAIN, TargetType.HOSTNAME}:
                normalize_hostname(target.value)
        except NetworkPolicyViolation as exc:
            return ValidationResult(valid=False, errors=[str(exc)])
        return ValidationResult(valid=True)

    async def estimate(self, request: AdapterRequest) -> ExecutionEstimate:
        return ExecutionEstimate(
            duration_seconds=self.default_timeout,
            risk="low",
            summary="Avaliação limitada, autenticada pelo âmbito e sem exploração.",
        )

    async def cancel(self, execution_id: str) -> None:
        self._cancelled.add(execution_id)

    async def health_check(self) -> HealthCheckResult:
        return HealthCheckResult(
            healthy=True,
            message="Adaptador carregado; nenhuma ligação é efetuada pelo health check.",
            checked_at=datetime.now(timezone.utc),
        )

    async def parse_output(self, raw_output: bytes) -> ParsedAdapterOutput:
        payload = json.loads(raw_output.decode("utf-8"))
        return ParsedAdapterOutput(
            findings=[NormalizedFinding.model_validate(item) for item in payload["findings"]],
            evidence=[NormalizedEvidence.model_validate(item) for item in payload["evidence"]],
            warnings=[AdapterWarning.model_validate(item) for item in payload["warnings"]],
            summary=AdapterExecutionSummary.model_validate(payload["summary"]),
        )

    def result(
        self,
        context: AdapterExecutionContext,
        *,
        findings: list[NormalizedFinding],
        evidence: list[NormalizedEvidence],
        warnings: list[AdapterWarning] | None = None,
        message: str,
    ) -> AdapterExecutionResult:
        summary = _real_summary(message, "warning" if warnings else "success")
        payload = {
            "findings": [item.model_dump(mode="json") for item in findings],
            "evidence": [item.model_dump(mode="json") for item in evidence],
            "warnings": [item.model_dump(mode="json") for item in warnings or []],
            "summary": summary.model_dump(mode="json"),
        }
        return AdapterExecutionResult(
            execution_id=context.execution_id,
            raw_output=json.dumps(payload, ensure_ascii=False, sort_keys=True).encode(),
            summary=summary,
        )

    def network(self, context: AdapterExecutionContext) -> tuple[NetworkExecutionPolicy, list[str]]:
        if not context.network_policy:
            raise ValueError("network_policy_missing")
        return context.network_policy, context.allowed_destinations

    @abstractmethod
    async def execute(self, context: AdapterExecutionContext) -> AdapterExecutionResult: ...


class AssetInventoryAdapter(JsonResultAdapter):
    configuration_model = AssetInventoryConfiguration
    target_types = [TargetType.IP, TargetType.DOMAIN, TargetType.HOSTNAME, TargetType.URL]
    adapter_code = "cyberaudit.asset_inventory"
    adapter_name = "Inventário técnico"
    category = "asset_inventory"
    description = "Consolida observações autorizadas sem descoberta de rede."

    async def execute(self, context: AdapterExecutionContext) -> AdapterExecutionResult:
        config = AssetInventoryConfiguration.model_validate(context.request.configuration)
        target = context.request.target.value
        observation: dict[str, Any] = {
            "target": target,
            "source": config.sources,
            "first_observed_at": datetime.now(timezone.utc).isoformat(),
            "last_observed_at": datetime.now(timezone.utc).isoformat(),
            "confidence": "high" if "platform" in config.sources else "medium",
        }
        if "dns" in config.sources and context.request.target.target_type != TargetType.IP:
            policy, allowed = self.network(context)
            hostname = urlsplit(target).hostname if "://" in target else target
            resolved = await SecureDnsResolver(policy, allowed).resolve(hostname or "", 443)
            observation["resolved_ips"] = resolved.addresses
        await context.progress_callback(75, "Inventário autorizado consolidado")
        evidence = [_evidence("structured_data", "Inventário técnico observado", observation)]
        return self.result(
            context,
            findings=[],
            evidence=evidence,
            message="Inventário técnico concluído sem descoberta de rede.",
        )


class DnsAssessmentAdapter(JsonResultAdapter):
    configuration_model = DnsAssessmentConfiguration
    target_types = [TargetType.DOMAIN, TargetType.HOSTNAME]
    adapter_code = "cyberaudit.dns_assessment"
    adapter_name = "DNS seguro"
    category = "dns_assessment"
    description = "Consulta apenas registos do domínio exato, com limites e cache por job."
    default_timeout = 30

    async def execute(self, context: AdapterExecutionContext) -> AdapterExecutionResult:
        config = DnsAssessmentConfiguration.model_validate(context.request.configuration)
        policy, allowed = self.network(context)
        resolver = SecureDnsResolver(policy, allowed)
        records: dict[str, list[str]] = {}
        warnings: list[AdapterWarning] = []
        for index, kind in enumerate(config.record_types):
            if await context.cancellation_check():
                raise asyncio.CancelledError
            try:
                answer = await resolver.query_records(context.request.target.value, kind)
                records[kind] = answer.values
            except NetworkPolicyViolation as exc:
                warnings.append(AdapterWarning(code="DNS_QUERY_BLOCKED", message=f"{kind}: {exc}"))
            await context.progress_callback(
                25 + int((index + 1) * 50 / len(config.record_types)), f"DNS {kind}"
            )
        findings: list[NormalizedFinding] = []
        if not records.get("CAA"):
            findings.append(
                _finding(
                    context,
                    source="dns.caa.missing",
                    title="Registo CAA não observado",
                    category="dns",
                    severity=Criticality.LOW,
                    description="Não foi observado um registo CAA no domínio avaliado.",
                    observed="ausente",
                    expected="CAA explícito quando aplicável",
                    remediation="Avaliar a publicação de CAA para limitar autoridades certificadoras.",
                    confidence="medium",
                )
            )
        if config.check_dnssec:
            try:
                dnskey = await resolver.query_records(context.request.target.value, "DNSKEY")
            except NetworkPolicyViolation:
                dnskey = None
            if not dnskey or not dnskey.values:
                findings.append(
                    _finding(
                        context,
                        source="dns.dnssec.not-observed",
                        title="DNSSEC não observado",
                        category="dns",
                        severity=Criticality.LOW,
                        description="A consulta limitada não observou chaves DNSSEC.",
                        observed="não observado",
                        expected="DNSSEC validável quando suportado",
                        remediation="Avaliar DNSSEC com o fornecedor DNS; tratar como recomendação.",
                        confidence="medium",
                    )
                )
        evidence = [_evidence("dns_records", "Registos DNS públicos observados", records)]
        return self.result(
            context,
            findings=findings,
            evidence=evidence,
            warnings=warnings,
            message=f"Avaliação DNS concluída com {resolver.query_count} consultas.",
        )


class TlsAssessmentAdapter(JsonResultAdapter):
    configuration_model = TlsAssessmentConfiguration
    target_types = [TargetType.DOMAIN, TargetType.HOSTNAME, TargetType.URL, TargetType.IP]
    adapter_code = "cyberaudit.tls_assessment"
    adapter_name = "TLS standard"
    category = "tls_assessment"
    description = "Inspeciona uma única ligação TLS autorizada e o certificado apresentado."
    default_timeout = 20

    async def execute(self, context: AdapterExecutionContext) -> AdapterExecutionResult:
        config = TlsAssessmentConfiguration.model_validate(context.request.configuration)
        policy, allowed = self.network(context)
        target = context.request.target.value
        parsed = urlsplit(target if "://" in target else f"//{target}")
        hostname = parsed.hostname or target
        sni = config.sni or (None if _is_ip(hostname) else hostname)
        if _is_ip(hostname) and not sni:
            raise ValueError("sni_required_for_ip_target")
        if config.sni:
            normalized_sni = normalize_hostname(config.sni)
            if not any(
                _scope_allows_hostname(normalized_sni, allowed_item) for allowed_item in allowed
            ):
                raise ValueError("sni_out_of_scope")
            sni = normalized_sni
        resolver = SecureDnsResolver(policy, allowed)
        destination = await resolver.resolve(hostname, config.port)
        peer_ip = destination.addresses[0]
        verified = True
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    peer_ip,
                    config.port,
                    ssl=ssl.create_default_context(),
                    server_hostname=sni,
                ),
                timeout=policy.connect_timeout,
            )
        except (ssl.SSLError, OSError):
            verified = False
            insecure_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            insecure_context.check_hostname = False
            insecure_context.verify_mode = ssl.CERT_NONE
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    peer_ip,
                    config.port,
                    ssl=insecure_context,
                    server_hostname=sni,
                ),
                timeout=policy.connect_timeout,
            )
        del reader
        ssl_object = writer.get_extra_info("ssl_object")
        if not ssl_object:
            writer.close()
            await writer.wait_closed()
            raise ValueError("tls_handshake_missing")
        der = ssl_object.getpeercert(binary_form=True)
        version = ssl_object.version() or "unknown"
        cipher_data = ssl_object.cipher()
        cipher = cipher_data[0] if cipher_data else "unknown"
        writer.close()
        await writer.wait_closed()
        certificate = x509.load_der_x509_certificate(der)
        now = datetime.now(timezone.utc)
        remaining_days = (certificate.not_valid_after_utc - now).days
        sans: list[str] = []
        try:
            san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            sans = san.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            pass
        hostname_matches = bool(sni and _hostname_matches(sni, sans))
        observed = {
            "peer_ip": peer_ip,
            "sni": sni,
            "verified_chain": verified,
            "hostname_matches": hostname_matches,
            "tls_version": version,
            "cipher": cipher,
            "subject": certificate.subject.rfc4514_string(),
            "issuer": certificate.issuer.rfc4514_string(),
            "sans": sans[:50],
            "not_before": certificate.not_valid_before_utc.isoformat(),
            "not_after": certificate.not_valid_after_utc.isoformat(),
            "sha256_fingerprint": certificate.fingerprint(hashes.SHA256()).hex(),
            "serial_number": format(certificate.serial_number, "x"),
        }
        findings: list[NormalizedFinding] = []
        if remaining_days < 0:
            findings.append(
                _finding(
                    context,
                    source="tls.certificate.expired",
                    title="Certificado TLS expirado",
                    category="tls",
                    severity=(
                        Criticality.HIGH if policy.allow_public_addresses else Criticality.MEDIUM
                    ),
                    description="O certificado apresentado terminou a sua validade.",
                    observed=certificate.not_valid_after_utc.isoformat(),
                    expected="certificado dentro da validade",
                    remediation="Renovar o certificado e validar a cadeia antes da substituição.",
                    confidence="high",
                )
            )
        elif remaining_days <= config.expiry_warning_days:
            findings.append(
                _finding(
                    context,
                    source="tls.certificate.expiring",
                    title="Certificado TLS próximo da expiração",
                    category="tls",
                    severity=Criticality.LOW,
                    description=f"O certificado expira dentro de {remaining_days} dias.",
                    observed=certificate.not_valid_after_utc.isoformat(),
                    expected=f"mais de {config.expiry_warning_days} dias de validade",
                    remediation="Planear e testar a renovação do certificado.",
                    confidence="high",
                )
            )
        if not hostname_matches:
            findings.append(
                _finding(
                    context,
                    source="tls.hostname.mismatch",
                    title="Hostname incompatível com o certificado",
                    category="tls",
                    severity=Criticality.HIGH,
                    description="O SNI autorizado não corresponde aos SAN observados.",
                    observed=", ".join(sans) or "SAN ausente",
                    expected=sni or hostname,
                    remediation="Emitir certificado que inclua o hostname autorizado.",
                    confidence="high",
                )
            )
        if not verified:
            findings.append(
                _finding(
                    context,
                    source="tls.chain.unverified",
                    title="Cadeia TLS não validada",
                    category="tls",
                    severity=Criticality.MEDIUM,
                    description="A validação padrão da cadeia não foi concluída.",
                    observed="cadeia não confiável ou incompleta",
                    expected="cadeia validável por trust store padrão",
                    remediation="Instalar a cadeia intermédia completa e usar uma CA adequada ao contexto.",
                    confidence="high",
                )
            )
        await context.progress_callback(80, "Certificado TLS recolhido")
        return self.result(
            context,
            findings=findings,
            evidence=[_evidence("tls_certificate", "Certificado TLS observado", observed)],
            message="Inspeção TLS limitada concluída.",
        )


class HttpSecurityHeadersAdapter(JsonResultAdapter):
    configuration_model = HttpAssessmentConfiguration
    target_types = [TargetType.URL, TargetType.DOMAIN, TargetType.HOSTNAME]
    adapter_code = "cyberaudit.http_security_headers"
    adapter_name = "Headers HTTP"
    category = "http_security_headers"
    description = "Analisa headers públicos com HEAD e GET limitado como fallback."

    async def execute(self, context: AdapterExecutionContext) -> AdapterExecutionResult:
        config = HttpAssessmentConfiguration.model_validate(context.request.configuration)
        policy, allowed = self.network(context)
        url = _target_url(context.request.target, config.scheme, config.path)
        client = SecureHttpClient(policy, allowed)
        response = await client.request(
            url, method="HEAD", cancellation_check=context.cancellation_check
        )
        if config.fallback_get and response.status_code in {405, 501}:
            response = await client.request(
                url, method="GET", cancellation_check=context.cancellation_check
            )
        sanitized = EvidenceSanitizer().sanitize_headers(response.headers)
        findings = _header_findings(context, response.headers, url)
        await context.progress_callback(80, "Headers HTTP analisados")
        return self.result(
            context,
            findings=findings,
            evidence=[
                NormalizedEvidence(
                    kind="http_headers",
                    summary="Headers HTTP sanitizados",
                    content=sanitized.content,
                    simulated=False,
                    mime_type="application/json",
                    metadata={
                        "redacted": sanitized.redacted,
                        "status_code": response.status_code,
                        "peer_ip": response.peer_ip,
                        "request_count": response.request_count,
                        "bytes_received": response.bytes_received,
                        "redirects": response.redirects,
                    },
                )
            ],
            message=f"Headers analisados com {response.request_count} pedido(s).",
        )


class WebTechnologyDetectionAdapter(JsonResultAdapter):
    configuration_model = TechnologyConfiguration
    target_types = [TargetType.URL, TargetType.DOMAIN, TargetType.HOSTNAME]
    adapter_code = "cyberaudit.web_technology_detection"
    adapter_name = "Tecnologias Web"
    category = "web_technology_detection"
    description = "Observa tecnologias apenas em headers e HTML limitado da página autorizada."

    async def execute(self, context: AdapterExecutionContext) -> AdapterExecutionResult:
        config = TechnologyConfiguration.model_validate(context.request.configuration)
        policy, allowed = self.network(context)
        url = _target_url(context.request.target, config.scheme, config.path)
        response = await SecureHttpClient(policy, allowed).request(
            url, method="GET", cancellation_check=context.cancellation_check
        )
        text = response.body.decode("utf-8", errors="replace")[:65_536]
        observations: list[dict[str, str]] = []
        server = first_header(response.headers, "server")
        powered = first_header(response.headers, "x-powered-by")
        if server:
            observations.append({"type": "server", "value": server, "confidence": "high"})
        if powered:
            observations.append({"type": "framework", "value": powered, "confidence": "high"})
        lower = text.lower()
        patterns = {
            "WordPress": "wp-content",
            "Drupal": "drupal-settings-json",
            "Next.js": "__next_data__",
            "React": "data-reactroot",
            "Shopify": "cdn.shopify.com",
        }
        for name, marker in patterns.items():
            if marker in lower:
                observations.append(
                    {"type": "web_technology", "value": name, "confidence": "medium"}
                )
        evidence = [_evidence("structured_data", "Tecnologias públicas observadas", observations)]
        await context.progress_callback(80, "Tecnologias públicas observadas")
        return self.result(
            context,
            findings=[],
            evidence=evidence,
            message="Deteção passiva concluída; nenhuma vulnerabilidade foi inferida.",
        )


class PublicConfigurationAdapter(JsonResultAdapter):
    configuration_model = PublicConfigurationConfiguration
    target_types = [TargetType.URL, TargetType.DOMAIN, TargetType.HOSTNAME]
    adapter_code = "cyberaudit.public_configuration"
    adapter_name = "Configuração pública"
    category = "public_configuration"
    description = "Obtém apenas um endpoint público selecionado numa enum fechada."

    async def execute(self, context: AdapterExecutionContext) -> AdapterExecutionResult:
        config = PublicConfigurationConfiguration.model_validate(context.request.configuration)
        policy, allowed = self.network(context)
        url = _target_url(context.request.target, config.scheme, config.endpoint)
        response = await SecureHttpClient(policy, allowed).request(
            url, method="GET", cancellation_check=context.cancellation_check
        )
        sanitizer = EvidenceSanitizer(redact_emails=True)
        excerpt = sanitizer.sanitize_text(response.body.decode("utf-8", errors="replace")[:32_768])
        findings: list[NormalizedFinding] = []
        if config.endpoint == "/.well-known/security.txt" and response.status_code == 404:
            findings.append(
                _finding(
                    context,
                    source="public.security-txt.missing",
                    title="security.txt não observado",
                    category="public_configuration",
                    severity=Criticality.LOW,
                    description="O endpoint selecionado respondeu 404.",
                    observed="HTTP 404",
                    expected="security.txt publicado quando aplicável",
                    remediation="Avaliar publicação segundo RFC 9116.",
                    confidence="high",
                    standards=[{"name": "RFC", "reference": "RFC 9116"}],
                )
            )
        if "traceback" in excerpt.content.lower() or "stack trace" in excerpt.content.lower():
            findings.append(
                _finding(
                    context,
                    source="public.stack-trace",
                    title="Stack trace público observado",
                    category="public_configuration",
                    severity=Criticality.MEDIUM,
                    description="A resposta pública contém indicadores de stack trace.",
                    observed="indicador textual de stack trace",
                    expected="página de erro genérica",
                    remediation="Desativar erros detalhados em produção e registar detalhes apenas internamente.",
                    confidence="medium",
                    standards=[{"name": "CWE", "reference": "CWE-209"}],
                )
            )
        await context.progress_callback(80, "Configuração pública observada")
        return self.result(
            context,
            findings=findings,
            evidence=[
                NormalizedEvidence(
                    kind="text_excerpt",
                    summary=f"Excerto sanitizado de {config.endpoint}",
                    content=excerpt.content,
                    simulated=False,
                    mime_type="text/plain",
                    metadata={"status_code": response.status_code, "redacted": excerpt.redacted},
                )
            ],
            message="Endpoint público explícito analisado.",
        )


class ExternalResultImportAdapter(JsonResultAdapter):
    configuration_model = ExternalImportAdapterConfiguration
    target_types = list(TargetType)
    adapter_code = "cyberaudit.external_result_import"
    adapter_name = "Importação externa"
    category = "external_result_import"
    description = "Normaliza uma importação privada previamente validada e confirmada."
    requires_network = False

    async def execute(self, context: AdapterExecutionContext) -> AdapterExecutionResult:
        ExternalImportAdapterConfiguration.model_validate(context.request.configuration)
        raise RuntimeError("external_imports_are_processed_by_import_service")


def _finding(
    context: AdapterExecutionContext,
    *,
    source: str,
    title: str,
    category: str,
    severity: Criticality,
    description: str,
    observed: str,
    expected: str,
    remediation: str,
    confidence: Literal["low", "medium", "high"],
    standards: list[dict[str, str]] | None = None,
) -> NormalizedFinding:
    return NormalizedFinding(
        title=title,
        description=description,
        category=category,
        severity=severity,
        confidence=confidence,
        affected_component=context.request.target.value,
        technical_impact=description,
        business_impact="A materialidade depende do contexto e da exposição do ativo.",
        remediation=remediation,
        validation_steps=["Repetir a mesma avaliação de baixo risco após a alteração."],
        evidence=[],
        source_identifier=source,
        logical_location=context.request.target.value,
        simulated=False,
        observed_value=observed,
        expected_value=expected,
        standards=standards or [],
        verification_status="observed",
    )


def _target_url(target: NormalizedTarget, scheme: str, path: str) -> str:
    if target.target_type == TargetType.URL:
        parsed = urlsplit(target.value)
        if path == "/":
            return target.value
        if parsed.path not in {"", "/", path}:
            raise ValueError("configured_path_differs_from_authorized_url")
        origin = f"{parsed.scheme}://{parsed.netloc}"
        return f"{origin}{path}"
    return f"{scheme}://{target.value}{path}"


def _header_findings(
    context: AdapterExecutionContext, headers: dict[str, list[str]], url: str
) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    required = {
        "strict-transport-security": (
            "HSTS ausente",
            "http.hsts.missing",
            "Strict-Transport-Security definido para respostas HTTPS",
        ),
        "content-security-policy": (
            "Content-Security-Policy ausente",
            "http.csp.missing",
            "CSP adequada à aplicação",
        ),
        "x-content-type-options": (
            "Proteção contra MIME sniffing ausente",
            "http.nosniff.missing",
            "X-Content-Type-Options: nosniff",
        ),
    }
    for name, (title, source, expected) in required.items():
        if name not in headers and (
            name != "strict-transport-security" or url.startswith("https://")
        ):
            findings.append(
                _finding(
                    context,
                    source=source,
                    title=title,
                    category="http_headers",
                    severity=Criticality.LOW,
                    description=f"O header {name} não foi observado na resposta avaliada.",
                    observed="ausente",
                    expected=expected,
                    remediation=f"Definir {name} após testar compatibilidade.",
                    confidence="high",
                )
            )
    cors_origin = first_header(headers, "access-control-allow-origin")
    cors_credentials = first_header(headers, "access-control-allow-credentials")
    if cors_origin == "*" and (cors_credentials or "").lower() == "true":
        findings.append(
            _finding(
                context,
                source="http.cors.wildcard-credentials",
                title="Política CORS excessivamente permissiva",
                category="http_headers",
                severity=Criticality.MEDIUM,
                description="Foram observados origem wildcard e suporte a credenciais.",
                observed="Access-Control-Allow-Origin: * com credentials",
                expected="origens explicitamente autorizadas",
                remediation="Substituir wildcard por allowlist de origens confiáveis.",
                confidence="high",
            )
        )
    for cookie in headers.get("set-cookie", []):
        name = cookie.split("=", 1)[0]
        lower = cookie.lower()
        if url.startswith("https://") and "secure" not in lower:
            findings.append(
                _finding(
                    context,
                    source=f"http.cookie.{name}.secure",
                    title=f"Cookie {name} sem atributo Secure",
                    category="http_headers",
                    severity=Criticality.MEDIUM,
                    description="Um cookie público foi observado sem Secure numa resposta HTTPS.",
                    observed=f"{name}: Secure ausente",
                    expected="atributo Secure",
                    remediation="Adicionar Secure após validar o fluxo da aplicação.",
                    confidence="high",
                )
            )
    return findings


def _is_ip(value: str) -> bool:
    try:
        __import__("ipaddress").ip_address(value)
    except ValueError:
        return False
    return True


def _hostname_matches(hostname: str, sans: list[str]) -> bool:
    normalized = normalize_hostname(hostname)
    for candidate in sans:
        lowered = candidate.rstrip(".").lower()
        if lowered == normalized:
            return True
        if lowered.startswith("*."):
            suffix = lowered[2:]
            if normalized.endswith(f".{suffix}") and normalized.count(".") == suffix.count(".") + 1:
                return True
    return False


def _scope_allows_hostname(hostname: str, value: str) -> bool:
    parsed = urlsplit(value if "://" in value else f"//{value}")
    candidate = parsed.hostname or value
    try:
        return normalize_hostname(candidate) == hostname
    except NetworkPolicyViolation:
        return False


def _default_inventory_sources() -> (
    list[Literal["platform", "dns", "http", "tls", "manual", "future_cmdb"]]
):
    return ["platform"]


def _default_dns_record_types() -> (
    list[Literal["A", "AAAA", "CNAME", "MX", "NS", "TXT", "CAA", "SOA"]]
):
    return ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "CAA", "SOA"]


REAL_ADAPTERS: list[ToolAdapter] = [
    AssetInventoryAdapter(),
    DnsAssessmentAdapter(),
    TlsAssessmentAdapter(),
    HttpSecurityHeadersAdapter(),
    WebTechnologyDetectionAdapter(),
    PublicConfigurationAdapter(),
    ExternalResultImportAdapter(),
]
