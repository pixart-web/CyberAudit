# PostgreSQL, Redis and queues

PostgreSQL uses bounded async pools, pre-ping, connection recycle, application naming and a
statement timeout. Migrations use a separate one-shot job. Production should add TLS verification,
least-privilege runtime/migration/backup roles, PITR, slow-query monitoring and managed failover.
High-volume event partitioning is deferred until measured retention/query profiles justify the
operational cost; lifecycle policies and indexed tenant/time columns exist first.

Redis is external in production and must require TLS, authentication, memory policy, persistence
appropriate to queues and a dedicated namespace/database. OIDC states and rate-limit keys are
hashed/namespaced with TTL. Dramatiq queues are named by workload and have bounded retries/time
limits. Job state remains PostgreSQL source-of-truth, enabling reconciliation after Redis restart.

A formal dead-letter store for every Dramatiq queue is not yet implemented. Job execution records
retain terminal errors, but connector/SOC support queues need a dedicated failed-message projection
before production scale.
