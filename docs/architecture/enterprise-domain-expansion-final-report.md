# Enterprise Domain Expansion — Implementation report

## Scope delivered

Migration `0009` adds tenant-bound connectors and executions, sanitized change
events, Identity/AD/Entra/SaaS inventories, common AWS/Azure/GCP resources,
Kubernetes/runtime posture, endpoint/mobile posture and eight-dimensional Zero
Trust assessments.

The API exposes connector lifecycle, domain inventories, posture/risk summaries,
bounded identity/cloud graphs and deterministic Zero Trust evaluation. The
worker accepts execution IDs only and revalidates organization, active state
and read-only policy before processing controlled local metadata.

## Security decisions

- secret values are rejected; only approved secret-manager references persist;
- connector and adapter types come from closed allowlists;
- all Enterprise adapters have network, process and filesystem activity
  disabled in this phase;
- API queries derive tenant from the authenticated user;
- cross-tenant and mutable connectors fail worker revalidation;
- recursive redaction precedes snapshots, hashes and change detection;
- unknown Zero Trust facts reduce confidence rather than fabricating posture;
- graphs are paginated and limited to 500 API nodes / 200 UI nodes;
- recommendations are advisory and no external system is modified.

## Validation performed

- clean PostgreSQL migration: `0001 → 0009`;
- complete seed chain plus idempotent Enterprise expansion seed;
- seed counts: 11 connectors, 3 identities, 3 cloud resources and one Zero
  Trust assessment;
- backend: 137 tests passed with 64% aggregate coverage;
- frontend: 15 tests passed;
- Ruff, Black and mypy passed;
- Next.js production build generated 91 routes;
- PostgreSQL, Redis, API and frontend local health checks passed;
- authenticated connector sync reached `completed` with
  `external_io=false`;
- Zero Trust demo returned score `38.33`, status `weak`, confidence `0.75`.

## Known limitations

Provider SDK collection, production secret resolution, partitioning for
multi-million inventories and a dedicated graph backend are not implemented.
Enterprise adapters are deliberately fixture/import-only. Digital Twin is a
bounded defensive explorer, not a full graph renderer. Zero Trust scoring does
not make access-control decisions.

## Recommended next phase

Perform production hardening: provider-specific read-only SDK collectors behind
egress policies, workload identity and secret-manager integration, PostgreSQL
RLS, partitioning and retention, signed connector releases, load tests, graph
projection workers, OIDC/MFA and independent security review. External
remediation must remain a separately approved capability.
