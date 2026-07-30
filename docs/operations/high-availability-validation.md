# High-availability validation

The target topology uses multiple stateless API/web replicas, independently
scaled workers, PostgreSQL primary/replica with an orchestrated failover, and
Redis with persistence and failover. Object storage and the secret manager must
be external HA services.

Validation removes one replica at a time, measures error rate and recovery,
checks session continuity, queue idempotency and database replica lag, then
records sanitized timestamps and metrics. This environment is not present
locally; HA remains blocked.
