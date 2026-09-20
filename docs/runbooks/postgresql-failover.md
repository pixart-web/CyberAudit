# PostgreSQL failover

1. Confirm primary loss and replica lag against the RPO threshold.
2. Quiesce writers and promote the approved replica through the database operator.
3. Update service discovery, rotate stale connections and keep runtime role/RLS.
4. Validate migrations, tenant isolation and queue idempotency.
5. Rebuild redundancy before closing the incident.
