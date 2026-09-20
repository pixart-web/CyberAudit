# ADR-024 — Production Readiness Closure

Status: accepted for implementation  
Evidence date: 2026-07-30  
Base branch: `codex/product-hardening-enterprise-readiness`  
Base commit: `fb3c9b86d12042032cfa6154d1c941bda531b4c3`

## Initial state

Phase 10 provides a tested hardening baseline, but it is not production-ready.
The baseline was independently repeated before this branch was created:

- Alembic head is `0010`;
- 153 backend tests passed with 64% repository coverage;
- 16 frontend tests, ESLint and the 92-route Next.js build passed;
- PR #3 is open, clean and has successful backend, frontend, migration and
  secret-scan checks.

The official blockers are WebAuthn interoperability, real OIDC providers,
PostgreSQL RLS, cross-tenant database enforcement, universal dead-letter
handling, external secrets/object storage, ephemeral runners, measured
backup/restore, HA/DR, verified release artefacts and backend coverage of at
least 75%.

## Decision

Production readiness is an evidence gate, not a boolean configuration flag.
CyberAudit will expose a `ProductionReadinessGate` whose checks have explicit
evidence, timestamps and one of `blocked`, `incomplete`, or `candidate`.
`approved` can only be recorded by a separate, named formal approval and will
never be inferred from passing automated checks.

Implementation follows these rules:

1. fail closed when tenant, identity, secret, signature, storage or runner
   context is absent;
2. preserve existing API contracts and migrations;
3. permit only fixed runner operations and immutable images;
4. store only public WebAuthn material and opaque secret/object references;
5. enable PostgreSQL RLS only with a dedicated runtime role and transaction
   tenant context;
6. sanitize DLQ metadata and revalidate tenant, schema, version, feature flag
   and idempotency before replay;
7. distinguish an executed local/representative test from external production
   evidence.

## Required environments

| Environment | Purpose | Required dependencies |
|---|---|---|
| development | normal local work | SQLite or PostgreSQL, Redis |
| test | deterministic unit/component tests | SQLite, in-memory fakes |
| integration | protocol and database enforcement | PostgreSQL, Redis, Keycloak, second OIDC IdP |
| production-like | promotion evidence | TLS proxy, PostgreSQL, Redis, S3-compatible storage, secret manager, workers, ephemeral runner |
| disaster-recovery-test | destructive isolated restore | independent database, storage and configuration |

Only synthetic data is permitted in integration, production-like and DR
environments.

## External dependencies and current availability

Promotion requires Keycloak plus a second IdP, Vault or an approved cloud
secret manager, S3-compatible storage, Docker and Kubernetes runtimes, an OCI
registry, signing identity and separate backup/DR infrastructure.

At branch creation Docker, Helm, Kubernetes, Vault, MinIO, `age`, Syft, Cosign,
Trivy and k6 were not installed in the execution environment. Code, manifests
and controlled tests can be produced here, but external exercises remain
blocked until those dependencies are supplied. The readiness gate must expose
that distinction.

## Implementation and test strategy

The order is:

1. critical coverage and negative-path authentication tests;
2. WebAuthn registration/authentication/step-up;
3. transaction-scoped RLS and cross-tenant database tests;
4. universal DLQ;
5. external provider and runner implementations with closed configuration;
6. operational gate, metrics, alerts and UI;
7. backup/restore/release/upgrade artefacts and executable validation;
8. final evidence report.

Tests cover success, denial, malformed data, replay, duplication, timeout,
unavailability, invalid tenant context and rollback where applicable. External
tests are opt-in and must skip with an explicit reason rather than silently
using a mock.

## Promotion criteria

Promotion to `Production-Ready Candidate` requires all mandatory gate checks,
backend coverage at or above 75%, no known high/critical vulnerability, clean
and upgrade migrations, verified restore checksums, measured RPO/RTO, real IdP
evidence, RLS database enforcement, signed artefacts and an executed
production-like/DR exercise.

Promotion to `approved` is outside automation and requires formal Security,
SRE, DBA, IAM and Product approval.

## Rollback

Application, worker and runner releases use immutable previous digests.
Database migrations are classified as reversible, conditionally reversible or
forward-fix-only. RLS changes are rolled back only by the migration role and
only after a verified backup. Disabling a security control is never an
automatic rollback.

## Risks and rejected alternatives

- Application-only tenant filters were rejected because one missed predicate
  can expose another tenant.
- A runtime role with `BYPASSRLS` was rejected.
- User-provided container commands or arguments were rejected.
- Secrets embedded in environment manifests or DLQ payloads were rejected.
- Automatically marking the system production-ready was rejected.
- Treating unit tests, manifests or unexecuted scripts as external evidence was
  rejected.

Residual risks include provider differences, browser authenticator behaviour,
managed-service failover characteristics, Kubernetes admission policy and
operational mistakes. They require real environment evidence and external
review.

## Operational responsibility

- IAM owns IdP, WebAuthn and recovery policy.
- Data Security/DBA own RLS roles, migrations, backup and restore.
- Platform Security owns secrets, storage and runner isolation.
- SRE owns HA, DR, observability and capacity evidence.
- Release Engineering owns SBOM, provenance, signing, upgrade and rollback.
- Security Engineering owns cross-tenant and adversarial validation.
- Product owns formal release acceptance; automation cannot grant it.

