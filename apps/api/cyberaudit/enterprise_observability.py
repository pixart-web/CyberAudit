"""Low-cardinality metrics for enterprise defensive capabilities."""

from prometheus_client import Counter, Gauge, Histogram

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

enterprise_connector_sync = Counter(
    "enterprise_connector_sync_total",
    "Read-only enterprise connector sync executions",
    ["connector_type", "result"],
)
enterprise_connector_sync_duration = Histogram(
    "enterprise_connector_sync_duration_seconds",
    "Enterprise connector sync duration",
    ["connector_type"],
)
enterprise_connector_records = Counter(
    "enterprise_connector_records_processed_total",
    "Sanitized enterprise records processed",
    ["domain"],
)
enterprise_inventory = Gauge(
    "enterprise_inventory_total",
    "Current enterprise inventory by low-cardinality domain and posture",
    ["domain", "posture"],
)
enterprise_risk_evaluations = Counter(
    "enterprise_risk_evaluations_total",
    "Deterministic risk evaluations",
    ["domain", "result"],
)
enterprise_graph_projection = Counter(
    "enterprise_graph_projection_total",
    "Bounded enterprise graph projections",
    ["domain", "result"],
)
enterprise_change_events = Counter(
    "enterprise_change_events_total",
    "Sanitized enterprise change events",
    ["domain", "severity"],
)
zero_trust_score = Gauge(
    "zero_trust_score",
    "Latest aggregate Zero Trust score",
    ["subject_type"],
)
