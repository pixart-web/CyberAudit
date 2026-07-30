import json
import logging
from typing import Any

from prometheus_client import Counter, Gauge, Histogram

from cyberaudit.redaction import redact

jobs_created = Counter("cyberaudit_jobs_created_total", "Jobs created", ["adapter_code"])
jobs_completed = Counter("cyberaudit_jobs_completed_total", "Jobs completed", ["adapter_code"])
jobs_failed = Counter("cyberaudit_jobs_failed_total", "Jobs failed", ["adapter_code", "code"])
jobs_cancelled = Counter("cyberaudit_jobs_cancelled_total", "Jobs cancelled", ["adapter_code"])
jobs_timed_out = Counter("cyberaudit_jobs_timed_out_total", "Jobs timed out", ["adapter_code"])
policy_denials = Counter("cyberaudit_policy_denials_total", "Policy denials")
approvals = Counter("cyberaudit_approvals_total", "Approval decisions", ["decision"])
findings_created = Counter(
    "cyberaudit_findings_created_total", "Findings created", ["adapter_code"]
)
findings_deduplicated = Counter(
    "cyberaudit_findings_deduplicated_total",
    "Findings deduplicated",
    ["adapter_code"],
)
job_duration = Histogram("cyberaudit_job_duration_seconds", "Job duration", ["adapter_code"])
queue_duration = Histogram("cyberaudit_queue_duration_seconds", "Time in queue", ["adapter_code"])
adapter_requests = Counter(
    "cyberaudit_adapter_requests_total", "Bounded network requests", ["scheme"]
)
adapter_bytes = Counter("cyberaudit_adapter_bytes_total", "Response bytes", ["scheme"])
dns_queries = Counter("cyberaudit_dns_queries_total", "Controlled DNS queries", ["record_type"])
redirects_blocked = Counter(
    "cyberaudit_redirects_blocked_total", "Redirects blocked by policy", ["reason"]
)
ssrf_blocks = Counter("cyberaudit_ssrf_blocks_total", "Network destinations blocked", ["reason"])
imports_total = Counter("cyberaudit_imports_total", "External result imports", ["result"])
retests_total = Counter("cyberaudit_retests_total", "Finding retests", ["result"])
evidence_redactions = Counter("cyberaudit_evidence_redactions_total", "Evidence values redacted")
asset_suggestions = Counter("cyberaudit_asset_suggestions_total", "Asset suggestions", ["result"])
assets_discovered = Counter(
    "cyberaudit_assets_discovered_total", "Assets suggested by discovery", ["source"]
)
services_observed = Counter("cyberaudit_services_observed_total", "Services observed", ["state"])
vulnerability_matches = Counter(
    "cyberaudit_vulnerability_matches_total", "Vulnerability matches", ["status"]
)
graph_analyses = Counter(
    "cyberaudit_graph_analyses_total", "Cyber Asset Graph analyses", ["result"]
)
attack_paths_analyzed = Counter(
    "cyberaudit_attack_paths_analyzed_total", "Candidate attack paths", ["status"]
)
feed_syncs = Counter(
    "cyberaudit_vulnerability_feed_syncs_total", "Vulnerability feed syncs", ["result"]
)
risk_calculations = Counter(
    "cyberaudit_risk_calculations_total", "Contextual risk calculations", ["version"]
)
applications_observed = Counter(
    "cyberaudit_applications_total", "Application inventory changes", ["result"]
)
api_endpoints_observed = Counter(
    "cyberaudit_api_endpoints_total", "API endpoints normalized", ["source"]
)
sbom_imports = Counter("cyberaudit_sbom_imports_total", "SBOM imports", ["result"])
sbom_components = Counter(
    "cyberaudit_sbom_components_total", "SBOM components normalized", ["type"]
)
secret_observations = Counter(
    "cyberaudit_secret_observations_total", "Secret observations", ["status"]
)
security_gate_evaluations = Counter(
    "cyberaudit_security_gate_evaluations_total",
    "Security gate evaluations",
    ["result"],
)
appsec_parser_errors = Counter(
    "cyberaudit_appsec_parser_errors_total", "AppSec parser errors", ["parser", "code"]
)
appsec_redactions = Counter(
    "cyberaudit_appsec_redactions_total", "AppSec values redacted", ["kind"]
)
appsec_assessment_duration = Histogram(
    "cyberaudit_appsec_assessment_duration_seconds",
    "AppSec assessment duration",
    ["adapter_code"],
)
authentication_events = Counter(
    "cyberaudit_authentication_total", "Authentication outcomes", ["method", "result"]
)
authorization_decisions = Counter(
    "cyberaudit_authorization_decisions_total",
    "Central authorization decisions",
    ["decision"],
)
connector_operations = Counter(
    "cyberaudit_connector_operations_total",
    "Connector operations",
    ["connector", "result"],
)
runner_operations = Counter(
    "cyberaudit_runner_operations_total",
    "Isolated runner operations",
    ["runner", "result"],
)
backup_operations = Counter(
    "cyberaudit_backup_operations_total", "Backup lifecycle operations", ["result"]
)
restore_operations = Counter(
    "cyberaudit_restore_operations_total", "Restore lifecycle operations", ["result"]
)
http_requests = Counter("http_requests_total", "HTTP responses", ["method", "route", "status"])
http_request_duration = Histogram(
    "http_request_duration_seconds", "HTTP request duration", ["method", "route"]
)
restore_last_verified = Gauge(
    "cyberaudit_restore_last_verified_timestamp_seconds",
    "Unix timestamp of the latest verified restore drill",
)
oidc_login_total = Counter("oidc_login_total", "OIDC login attempts")
oidc_login_failures_total = Counter("oidc_login_failures_total", "OIDC login failures")
webauthn_registration_total = Counter(
    "webauthn_registration_total", "WebAuthn registration outcomes", ["result"]
)
webauthn_authentication_total = Counter(
    "webauthn_authentication_total", "WebAuthn authentication outcomes", ["result"]
)
rls_denials_total = Counter("rls_denials_total", "PostgreSQL RLS or context denials")
cross_tenant_denials_total = Counter(
    "cross_tenant_denials_total", "Cross-tenant access denials", ["layer"]
)
dead_letter_messages_total = Counter(
    "dead_letter_messages_total", "Dead-letter messages", ["queue"]
)
dead_letter_replays_total = Counter(
    "dead_letter_replays_total", "Dead-letter replay outcomes", ["result"]
)
secret_provider_failures_total = Counter(
    "secret_provider_failures_total", "Secret-provider failures", ["provider"]
)
object_storage_failures_total = Counter(
    "object_storage_failures_total", "Object-storage failures", ["provider"]
)
runner_executions_total = Counter("runner_executions_total", "Runner executions", ["runner"])
runner_failures_total = Counter("runner_failures_total", "Runner failures", ["runner", "code"])
backup_success_total = Counter("backup_success_total", "Successful backups")
backup_failure_total = Counter("backup_failure_total", "Failed backups")
restore_success_total = Counter("restore_success_total", "Successful restores")
restore_failure_total = Counter("restore_failure_total", "Failed restores")
ha_failover_total = Counter("ha_failover_total", "HA failover outcomes", ["component", "result"])
dr_exercise_total = Counter("dr_exercise_total", "DR exercise outcomes", ["result"])
release_signature_failures_total = Counter(
    "release_signature_failures_total", "Release signature failures"
)
production_readiness_blockers = Gauge(
    "production_readiness_blockers", "Current mandatory readiness blockers"
)
rls_enabled = Gauge("rls_enabled", "Whether PostgreSQL RLS is required by configuration")
tenant_context_missing_total = Counter(
    "tenant_context_missing_total", "Database operations rejected without tenant context"
)
backup_last_success_timestamp_seconds = Gauge(
    "backup_last_success_timestamp_seconds", "Unix timestamp of the latest verified backup"
)
database_replica_lag_seconds = Gauge(
    "database_replica_lag_seconds", "Observed PostgreSQL replica lag"
)
release_sbom_present = Gauge("release_sbom_present", "Whether the running release has an SBOM")
release_signature_valid = Gauge(
    "release_signature_valid", "Whether the running release signature was verified"
)
test_coverage_percent = Gauge("test_coverage_percent", "Reported backend test coverage percentage")

logger = logging.getLogger("cyberaudit.execution")
SENSITIVE = {"token", "password", "secret", "configuration", "raw_output"}


def structured_event(event: str, **fields: Any) -> None:
    safe = redact({key: value for key, value in fields.items() if key not in SENSITIVE})
    logger.info(json.dumps({"event": event, **safe}, default=str, sort_keys=True))
