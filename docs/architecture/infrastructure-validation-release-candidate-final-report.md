# Infrastructure validation and release candidate report

Date: 2026-08-03

Branch: `codex/readiness-infrastructure-enablement`

Base commit: `1774053`
Classification: **blocked — not a release candidate**

## Executed environment

The local macOS/arm64 host has 10 logical CPUs and 32 GiB RAM. Colima provides
a four-CPU/eight-GiB Docker runtime. The version-pinned tool inventory is stored
in `artifacts/readiness/environment-check.json`; 21 required checks were ready.

The production-like Compose environment ran PostgreSQL 16.9, TLS Redis,
persistent initialized/unsealed Vault, private TLS MinIO, Keycloak, API, web,
worker, Nginx edge, Prometheus, Grafana and OpenTelemetry. A Kind cluster ran the
restricted Kubernetes Job validation.

## Results observed

| Control | Observed result | Classification |
|---|---|---|
| Keycloak | HTTPS discovery and PKCE S256; bounded Viewer/Analyst/Admin mappings | partial; browser matrix and second IdP blocked |
| WebAuthn | backend control exists | blocked; trusted browser ceremony not executed |
| PostgreSQL RLS | missing tenant empty, own tenant visible, foreign rows/join denied, runtime has no superuser/BYPASSRLS | partial matrix |
| DLQ | 9 synthetic worker scenarios, dedupe/replay/discard/redaction/tenant isolation | passed |
| Vault/MinIO | real provider resolution and encrypted tenant-bound object roundtrip | passed subset |
| Docker/Kind runners | non-root, read-only, bounded, no socket/privilege/default egress | passed primitives |
| Backup/restore | encrypted archive; isolated counts and MinIO checksums match | RTO 1 s, observed RPO 0 s; human review pending |
| HA | application-tier exercise | partial; data layer not highly available |
| DR | isolated restore on same host | blocked; not a second environment |
| SBOM | 12 component documents in CycloneDX/SPDX | partial; frozen release bundle pending |
| Trivy | 82 HIGH, 17 CRITICAL, zero detected secrets | failed; no risk acceptance recorded |
| k6 | 2,679 public synthetic requests, 0 errors, about 132.7 req/s, p95 41.1 ms | partial; authenticated scenarios pending |
| Tests/coverage | frontend 16/16; backend 176 passed, 1 opt-in skipped; PostgreSQL RLS SQL passed | backend line coverage 69%, below 75% |
| Signing/provenance | protected workflow defined | blocked until frozen candidate and GitHub OIDC |
| External assessment | pack prepared | blocked pending independent assessor |

All figures above must be checked against the checksum-bound evidence manifest;
this document is not itself gate approval.

## Gate and release status

The gate consumes tenant-scoped database evidence and the external manifest.
Artifact existence alone is insufficient: declared status, checksum, time,
environment, version, expiry and reviewer are validated. Human-review controls
reject `automation:*` reviewers. Current vulnerability and coverage results
prevent candidate state, in addition to external/browser/HA/DR/signing controls.

No tag or GitHub release was created. The local `release-candidate` target first
executes the gate and therefore stops before publication. Keyless signing and
immutable publication exist only in the protected tag workflow.

## Actions required

1. Validate a genuinely independent second IdP and the complete OIDC matrix.
2. Execute WebAuthn with trusted browser origin and physical authenticator.
3. Complete RLS and authenticated load matrices.
4. Exercise PostgreSQL/Redis/MinIO failover and DR on a second environment.
5. Remediate HIGH/CRITICAL vulnerabilities or approve narrow versioned risks.
6. Obtain independent security assessment and human evidence reviews.
7. Freeze a clean commit, run installation/upgrade/rollback, generate bundle
   SBOM/provenance, sign and verify through the protected workflow.

Fase 11 must not start while the gate differs from `candidate` or a verifiable
release candidate does not exist.
