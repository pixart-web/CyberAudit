# High-availability validation

The target topology uses multiple stateless API/web replicas, independently
scaled workers, PostgreSQL primary/replica with an orchestrated failover, and
Redis with persistence and failover. Object storage and the secret manager must
be external HA services.

Validation removes one replica at a time, measures error rate and recovery,
checks session continuity, queue idempotency and database replica lag, then
records sanitized timestamps and metrics.

`make readiness-ha-test` exercised two APIs and two workers behind Nginx. It
removed one verified Compose replica of each service, confirmed API continuity
through Docker DNS re-resolution, confirmed the second worker remained active,
and restored the scale. The result is deliberately `partial`: PostgreSQL
primary/replica, Redis failover and distributed MinIO were not available. The
same-host application-tier exercise must not be approved as full HA.
