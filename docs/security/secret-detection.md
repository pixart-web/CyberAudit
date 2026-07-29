# Secret Detection

Detectors use a bounded allowlist of patterns. On a match, CyberAudit calculates
a SHA-256 fingerprint and retains type, location, length, confidence and a short
mask. The raw candidate is discarded before persistence and evidence rendering.

The registered Phase 5 adapter exposes only `scenario=synthetic_demo`; source
text is not accepted in job configuration. Real repository bytes require the
future ephemeral storage-to-worker channel.

Access requires `secrets.read`; state review requires `secrets.review`. Demo
observations are explicitly synthetic/revoked.
