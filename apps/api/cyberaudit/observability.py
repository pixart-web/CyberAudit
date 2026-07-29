import json
import logging
from typing import Any

from prometheus_client import Counter, Histogram

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

logger = logging.getLogger("cyberaudit.execution")
SENSITIVE = {"token", "password", "secret", "configuration", "raw_output"}


def structured_event(event: str, **fields: Any) -> None:
    safe = {key: value for key, value in fields.items() if key not in SENSITIVE}
    logger.info(json.dumps({"event": event, **safe}, default=str, sort_keys=True))
