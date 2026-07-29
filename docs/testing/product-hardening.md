# Product hardening validation

Automated coverage includes unsafe production configuration, redaction, cross-tenant authorization,
step-up decisions, password policy, PKCE/TOTP/recovery primitives, connector contracts and URL
scope, runner operation closure, upload/path/archive controls, storage tenancy, lifecycle/legal hold,
telemetry minimization and signed offline licences.

CI runs backend lint/type/test, frontend lint/test/build, a clean PostgreSQL migration, dependency
audits and a bounded secret signature scan. `infrastructure/testing/load_smoke.py` performs a
localhost-only concurrency smoke test with capped request/concurrency values.

The acceptance gate remains honest:

- provider OIDC interoperability needs a real test tenant;
- Vault/cloud secrets and cloud object storage need workload identity;
- ephemeral runners need a container/Kubernetes controller and adversarial isolation testing;
- HA, RPO and RTO need multi-node infrastructure and a timed restore drill;
- the 75% repository-wide coverage target is not yet reached because legacy router/worker modules
  remain below that threshold.
