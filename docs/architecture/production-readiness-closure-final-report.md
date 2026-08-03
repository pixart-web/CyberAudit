# Production Readiness Closure — evidence report

Date: 2026-07-30

Branch: `codex/production-readiness-closure`

Base: `fb3c9b86d12042032cfa6154d1c941bda531b4c3`

Classification: **incomplete / blocked**, not Production Ready

> Historical baseline report. Infrastructure capabilities have since been
> exercised on `codex/readiness-infrastructure-enablement`; current results and
> remaining blockers are recorded in
> `infrastructure-validation-release-candidate-final-report.md`. Statements
> below about unavailable local tools describe the earlier baseline only.

## Implemented and locally verified

| Control | Evidence | Result |
|---|---|---|
| Baseline | Phase 10 tests/build and PR checks inspected before changes | passed |
| WebAuthn foundation | single-use tenant/purpose challenge tests; registration option test | passed, browser ceremony pending |
| OIDC protocol | signed RS256 representative token, PKCE, nonce, verified email, groups/role mapping | passed, real IdPs pending |
| PostgreSQL RLS | migrations 0011–0015; restricted role; missing-context reads empty; tenant reads isolated; cross-tenant update denied | passed locally |
| Runtime role | API `/assets` smoke with signed tenant token under `cyberaudit_runtime` returned five own-tenant assets | passed locally |
| DLQ | strict envelope, deduplication, sanitization, step-up and closed replay-handler tests | passed; production handlers pending |
| Vault | KV v2 MockTransport test with fixed token file, HTTPS, metadata and unsafe-path denial | implementation passed; real Vault pending |
| S3 | SDK boundary test for tenant prefix, checksum, size, encryption metadata and signed URL expiry | implementation passed; real MinIO/S3 pending |
| Runners | immutable digest-pinned spec; no command/args/mount/socket/network; bounded resources | implementation passed; controllers pending |
| Frontend | lint, 16 component tests, TypeScript/Next production build with 92 routes | passed |
| Backend | Ruff, Black, mypy; 171 tests passed, 1 opt-in test skipped in global run; 75.01% runtime coverage | passed |
| PostgreSQL integration | opt-in RLS test executed separately | 1 passed |
| Migrations/seed | Alembic at `0015 (head)`; hardening seed executed | passed |

The backend runtime coverage measured by the complete suite is **75.01%**,
above the mandatory 75% target. Demo-data CLI seed loaders are measured by the
migration/seed smoke workflow rather than the runtime unit-coverage metric.

## External blockers

The workstation does not provide Docker, Kubernetes, Helm, Vault, MinIO,
`syft`, `cosign`, `trivy` or `k6`. No external IdP tenant/credentials or
production-like HA topology was supplied.

Consequently the following checks are blocked and must not be recorded as
passed: Keycloak; a second real IdP; browser WebAuthn; real Vault rotation and
expiry; real object retention/isolation; Docker and Kubernetes execution and
cleanup; backup/restore drill; HA/DR; load/stress/chaos; external security
validation; generated SBOMs; signatures; provenance; release candidate; and
upgrade/rollback.

## Gate behavior

`GET /api/v1/operations/production-readiness` reads tenant-scoped, expiring
evidence for every mandatory check. Missing or expired evidence produces a
blocker. Complete evidence produces only `candidate`; `approved` additionally
requires an explicit, reviewed `ProductionReadinessApproval`. The application
never self-certifies.

## Security decisions

- Tenant context comes from a verified token or a minimal audited OIDC slug
  bootstrap function, never from a request organization UUID.
- The API pool assumes a `NOLOGIN`, `NOBYPASSRLS`, non-superuser runtime role;
  migration and backup roles remain separate.
- WebAuthn stores public credential material only; step-up tokens accept only
  WebAuthn or explicitly phishing-resistant OIDC.
- Vault/S3/controller endpoints are deployment configuration, not user input.
- Runners use closed operation-to-image mappings and cannot receive shell
  commands, images, paths or environment variables.
- DLQ replay is version/feature/handler checked, step-up protected and fails
  closed when no handler exists.
- Release CI signs immutable digests/files and verifies identity before
  publication; this workflow has not been executed on this branch.
