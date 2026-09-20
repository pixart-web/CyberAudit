# Object storage outage

1. Pause uploads/exports and preserve their idempotency keys.
2. Check bucket health, workload identity, TLS and quota from the server boundary.
3. Do not switch to public buckets or filesystem storage in production.
4. On recovery, verify checksums, tenant prefixes and lifecycle policies.
