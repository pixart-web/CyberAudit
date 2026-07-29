# Disaster recovery

Recommended targets are RPO 24 hours and RTO 8 hours for Professional, and contractual targets for
Enterprise. The reference topology uses multi-zone stateless API/web replicas, redundant workers,
managed PostgreSQL with point-in-time recovery, Redis with authentication/TLS and durable object
storage.

During an incident:

1. declare the incident and freeze deployments;
2. establish the last trustworthy database/object/secret versions;
3. deploy an isolated recovery control plane;
4. restore database and objects, then run migrations once;
5. rotate session/JWT, connector and storage credentials if compromise is possible;
6. validate tenant isolation, authorization, evidence hashes and queued-job idempotency;
7. switch traffic gradually, monitor SLOs and preserve the failed environment for investigation.

Failback is a separate approved change. A recovery is incomplete until a signed drill report exists.
