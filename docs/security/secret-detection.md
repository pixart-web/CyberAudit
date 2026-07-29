# Secret Detection

Detectors use a bounded allowlist of patterns. On a match, CyberAudit calculates
a SHA-256 fingerprint and retains type, location, length, confidence and a short
mask. The raw candidate is discarded before persistence and evidence rendering.

Access requires `secrets.read`; state review requires `secrets.review`. Demo
observations are explicitly synthetic/revoked.
