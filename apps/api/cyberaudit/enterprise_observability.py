"""Low-cardinality metrics for enterprise defensive capabilities."""

from prometheus_client import Counter, Histogram

security_events_ingested = Counter(
    "cyberaudit_security_events_ingested_total",
    "Normalized defensive events ingested",
    ["source", "event_type"],
)
detections_created = Counter(
    "cyberaudit_detections_created_total",
    "Detection alerts created",
    ["severity"],
)
incidents_created = Counter(
    "cyberaudit_incidents_created_total",
    "Incidents created",
    ["severity"],
)
grc_workflows = Counter(
    "cyberaudit_grc_workflows_total",
    "GRC workflow operations",
    ["workflow", "result"],
)
ai_requests = Counter(
    "cyberaudit_ai_requests_total",
    "Advisory AI requests",
    ["service", "provider", "result"],
)
enterprise_operation_duration = Histogram(
    "cyberaudit_enterprise_operation_duration_seconds",
    "Enterprise operation duration",
    ["module", "operation"],
)
