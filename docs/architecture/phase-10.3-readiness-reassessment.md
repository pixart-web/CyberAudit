# Phase 10.3 — ProductionReadinessGate reassessment (10.3.14)

This is a factual reassessment, not a release decision. The gate remains
authoritative (ADR-024/ADR-025); Phase 10.3 does not override it, and Phase
11 stays blocked until it clears (sections 47–48 of the implementation
brief).

## What was actually re-run in this session

All of the following used real infrastructure (a locally run PostgreSQL
16.9 container, Docker image builds, Trivy) or the existing pytest suite —
nothing here is a re-stated claim from a previous run:

| Check | Previous evidence | Refreshed evidence | Result |
|---|---|---|---|
| `migrations` | head `0015` (2026-08-03) | head `0017`, applied clean on a fresh PostgreSQL 16.9 | **passed** |
| `coverage` | 74.23% (`failed`, pre-Phase-10.3) | 76.46%, 267 backend tests | **passed** — was the one blocker this phase actually closed |
| `rls` | own_assets=5, 0 tables without RLS (2026-08-03) | re-run against the current schema (includes `ai_model_manifests`, `engagement_notes`, `engagement_timeline_entries`, `reports`, `report_sections`): still 0 tenant tables without RLS or without a runtime policy | **passed** |
| `cross_tenant_tests` | 8 tests, layers up to `execution_api` | 13 tests: added `ai_agents` (tool-gateway tenant scoping) and `engagement_reporting` (report generation, timeline events) layers | **passed** |
| `vulnerabilities` | 82 high / 17 critical (2026-08-03, stale — predates this phase's CVE fixes) | Rebuilt `cyberaudit-readiness-{api,web,worker}` images with the CVE fixes from ADR (Phase 10.3.0: `next`≥15.5.24, `cryptography`≥50) and bumped base image tags (`python:3.12.14-slim-bookworm`, `node:22.20.0-alpine3.22`); full Trivy fs+image+config scan: 165 high / 15 critical remain | **failed** (see below) |

`secret_provider`, `object_storage`, `docker_runner`, `kubernetes_runner`,
`configuration`, `oidc_keycloak`, `dlq` were not re-verified in this
session — their evidence files are untouched from the prior run and are
carried forward as-is (all were already `passed`).

## Why `vulnerabilities` is still `failed`

`pip-audit` and `pnpm audit --audit-level high` both report **zero** known
vulnerabilities in CyberAudit's own application dependencies as of this
session — every application-level CVE found in the Phase 10.3.0 baseline
stabilization (`next`, `cryptography`) is fixed. The remaining 165
high/15 critical findings are entirely in **upstream Debian bookworm base
packages** (`perl-base`, `tar`, `libsqlite3-0`, `zlib1g`, `libssl3`/
`libcrypto3`). `apt-cache policy` inside the base image confirms no newer
candidate package version exists yet — Debian has not backported a fix.
This is not fixable by editing CyberAudit's own code or dependency pins;
it requires either an upstream Debian security update or a different base
image strategy (e.g., distroless, or a different distribution), which is a
larger decision than this phase's scope. It is documented here rather than
worked around, and — per the gate's own design (see below) — cannot be
marked `passed` by this session regardless.

## Why the gate cannot be "passed" from this session, structurally

`scripts/readiness/build-evidence-manifest.py` requires, for any check in
`HUMAN_REVIEW_REQUIRED` (`oidc_second_provider`, `webauthn`, `backup`,
`restore`, `ha`, `dr`, `signing`, `provenance`, `vulnerabilities`,
`release_validation`, `upgrade`, `rollback`, `external_assessment`), a
`reviews/<check_id>.json` file whose `reviewer` field does **not** start
with `automation:` and whose `artifact_checksum` matches the evidence
file. There is no path for an automated session — this one included — to
self-approve these checks. That is by design (ADR-025) and this
reassessment does not attempt to route around it.

## Current gate state

```json
{
  "state": "blocked",
  "checks": {
    "configuration": "passed", "coverage": "passed", "cross_tenant_tests": "passed",
    "dlq": "passed", "docker_runner": "passed", "kubernetes_runner": "passed",
    "migrations": "passed", "object_storage": "passed", "oidc_keycloak": "passed",
    "rls": "passed", "secret_provider": "passed",
    "vulnerabilities": "failed",
    "oidc_second_provider": "blocked", "webauthn": "blocked", "backup": "blocked",
    "restore": "blocked", "ha": "blocked", "dr": "blocked", "sbom": "blocked",
    "signing": "blocked", "provenance": "blocked", "release_validation": "blocked",
    "upgrade": "blocked", "rollback": "blocked", "external_assessment": "blocked"
  }
}
```

11 of 24 mandatory checks pass with fresh, real evidence. 1 fails
honestly (upstream OS CVEs, no code-level fix available, needs a human
risk-acceptance decision or a base-image strategy change). 12 remain
blocked because they require infrastructure and human sign-off (a second
OIDC provider, real WebAuthn hardware ceremonies, encrypted backup/restore
drills, HA/DR failover drills, SBOM/signing/provenance pipeline execution,
an independent external security assessment) that were out of scope to
fabricate in this development session — and, per the manifest builder's
own design, could not have been self-approved even if attempted.

## Recommendation

**Not production ready.** Phase 10.3's own features (sovereign AI runtime,
agent framework, engagement/reporting domain, offline update bundles,
loopback-by-default packaging) are complete and tested on their own terms
(see the phase's git history and ADRs 026–030). They do not, and are not
claimed to, change the ProductionReadinessGate's blocked state, which
depends on infrastructure and human review this session does not have
authority or ability to provide.
