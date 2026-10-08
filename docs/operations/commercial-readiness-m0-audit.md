# M0 — Deployment reality audit (2026-10-08)

Scope: what is actually running at `https://cyberaudit.pixart.pt`, why it behaves like a demo, and why
records/users cannot be created. Method: public, read-only HTTP probes + repository analysis.
**No server access was available in this session** (no SSH host configured); items marked *unverified*
need an operator with server access (commands in `deploy/hetzner-evaluation/RUNBOOK.md`).

## Evidence
| Probe | Result |
|---|---|
| `GET /openapi.json` on the live site | 52 paths, version `1.0.0` |
| Same extraction from `origin/main` (`d3a182f`, "Initial CyberAudit platform") | 52 paths, version `1.0.0`, **identical path set** |
| Same extraction from `codex/security-os-product-completion` (`a9fe510`) | 305 paths |
| `/ready`, `/health` | 200 (PostgreSQL + Redis reachable) |
| `/docs`, `/openapi.json` | publicly served |

## Discrepancy report
| Component | Repository state | Deployed state | Problem | Action |
|---|---|---|---|---|
| Git SHA | 59 commits ahead of `main` across PRs #1–#8, none merged | `main` (`d3a182f`) — verified by identical OpenAPI path set | ~250 endpoints, all Workspaces, RBAC catalog, Cyber AI, reporting not deployed | Deploy a reviewed release via `deploy/hetzner-evaluation` |
| Frontend | Create forms existed only for Engagements and Jobs | Same | `/users`, `/clients`, `/assets`, `/scopes`, `/organizations` were **list-only** (`ResourcePage` without a form) — backend `POST` existed, no UI called it | Schema-driven `CreateForm` + real admin UIs (this branch) |
| API / organizations | `POST /organizations` returned the caller's own org and answered 403 for any other slug | Same | Creating an organization was impossible by construction (stub) | `POST /platform/organizations` + `platform.manage` (this branch) |
| API / users | `POST /users` only; duplicate e-mail → HTTP 500; no role list, edit, disable, reset, revoke | Same | No user lifecycle | `GET /roles`, `PATCH /users/{id}`, reset-password, revoke-sessions, 409 on duplicates |
| Authentication | Login form **prefilled** `admin@cyberaudit.local` / `ChangeMe123!` | Same (code path identical) | Default administrator credentials shown to every visitor and valid if the demo seed ran | Defaults removed; seed refuses the default password outside development; rotation CLI |
| Bootstrap | No first-run flow; only the demo seed (fixed password) | Unknown *(unverified)* | No safe way to create the first admin | Token-gated, one-shot `/setup` + `admin_cli rotate-password` |
| RBAC | Permissions created only by per-phase demo seeds bound to org `cyberaudit-demo` | Likely partial *(unverified)* | A real install's administrator would be locked out of SOC/Risk/GRC/Cloud (403) | `rbac_catalog.py` (161+ codes, test-guarded) + idempotent `ensure_rbac` |
| Assessment catalog | Scan profiles seeded only for the demo org | Likely empty for real tenants *(unverified)* | Jobs unusable on real installs | `provisioning.py`, run on tenant creation and via CLI |
| Workers | `docker-compose.production.yml` starts only `cyberaudit.worker` | Unknown *(unverified)* | SOC detection, asset-intelligence, enterprise and identity/cloud queues never consumed | Evaluation compose starts all four worker modules |
| UI identity | Header hardcoded `ACME-2026-01`, "CyberAudit Demo", "Modo Cliente", "Administrador" | Same | Looks like a demo; wrong user/org shown | Header reads `/auth/me` and `/organizations` |
| Reporting | Report rows + sections, no export | Same | Nothing a customer can take away | PDF export from recorded data |
| Docs exposure | Swagger/OpenAPI always on unless `production_like` | Public | API surface disclosed | `API_DOCS_ENABLED=false` in the evaluation profile |
| Licensing / AI runtime | Present in repo | not deployed | — | not changed in this milestone |

## Root causes (answers to the M0 questions)
1. **Deployed SHA:** `main` / `d3a182f` (route-set equivalence).
2. **Why it looks like a demo:** it *is* the initial platform, plus hardcoded demo identity strings and prefilled demo credentials in the UI.
3. **Why users cannot be created:** the Users screen has no creation UI; the API accepts only a minimal `POST` and crashes (500) on duplicates.
4. **Why records cannot be created:** same pattern for clients/assets/scopes; organizations are a stub endpoint.
5. **Not caused by:** a read-only/demo flag, RBAC being disabled, or RLS — none of those switches exist; authorization worked correctly in every test.
6. **Unverified (need server access):** schema revision, container/image digests, whether the demo seed ran, active admin accounts, volumes, backups, worker presence, Traefik network/certresolver names.
