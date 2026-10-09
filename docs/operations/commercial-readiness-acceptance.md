# Commercial-readiness acceptance record (branch `codex/real-product-commercial-readiness`)

Environment: local, **real PostgreSQL 16** (docker, disposable), Alembic `upgrade head` (0017), uvicorn API, Dramatiq worker
(all four modules), Next.js dev server, real browser pane. Date: 2026-10-08. Not executed on the Hetzner host.

## End-to-end customer journey (item 58)
| Step | Result | Evidence |
|---|---|---|
| Bootstrap first admin (wrong token rejected, right token accepted, second attempt 403) | PASS | browser + `test_bootstrap_is_token_gated_and_one_shot` |
| Login / persistence across logout+relogin | PASS | browser, API |
| Create organization (platform) | PASS | `POST /platform/organizations` (org "Contoso Labs") + UI form |
| Create user, assign role | PASS | browser: user "Maria Silva" (Auditor) |
| Login as new user; RBAC (403 on /users, 403 on platform) | PASS | API |
| Create client / engagement / scope / scope-target (invalid target → 422) | PASS | API + browser (client) |
| Upload signed authorization PDF; engagement → authorized → active | PASS | API (policy gate enforced) |
| Create asset | PASS | API |
| Run supported assessment | PARTIAL | live adapters blocked local test target (`url_port_blocked` — correct policy); supported **import** path executed instead: CSV → preview → confirm → worker job completed → 3 findings (marked *unverified*) |
| Evidence linking, risk, graph context, compliance view | NOT RE-TESTED | exercised in the earlier Phase 10.4.1 pass on seeded data; not part of this journey |
| Cyber AI | BLOCKED | no local model installed; runtime reports `disabled` (honest degraded state) |
| Report generated + PDF exported | PASS | browser "Exportar PDF" → 200, `report.exported` audited; cover page visually checked |
| Restart API+worker, data intact | PASS | clients 2 / findings 3 / users 2 / reports 1 |
| Audit log | PASS | 16 distinct action types recorded |
| Tenant isolation (A↔B: users, clients, findings, engagement, report, PDF, PATCH user) | PASS | all 404/empty; incl. platform admin of A cannot see B |

## Functional matrix (tested = ✔ on real DB)
| Module | Create | Read | Update | Archive/Delete | Browser E2E | Status |
|---|---|---|---|---|---|---|
| Organizations | ✔ | ✔ | – | N/A (lifecycle not implemented) | ✔ (form) | partial |
| Users | ✔ | ✔ | ✔ (role/status/name) | disable | ✔ | done |
| Roles | built-in catalog | ✔ | N/A | N/A | ✔ | done |
| Clients | ✔ | ✔ | ✔ PATCH (API, no UI) | API `DELETE` (soft), no UI | ✔ create/list | partial |
| Engagements | ✔ (UI pre-existing) | ✔ | status only | – | not re-run | partial |
| Scope / targets | ✔ | ✔ | ✗ | ✗ | form added, API ✔ | partial |
| Assets | ✔ | ✔ | ✔ PATCH (pre-existing, no UI) | ✔ archive (API, no UI) | form added, API ✔ | partial |
| Jobs / imports | ✔ | ✔ | cancel/retry (API) | – | import UI exists (upload → preview → confirm), not re-run | partial |
| Findings | via import/job only | ✔ | ✗ | ✗ | list ✔ | partial |
| Evidence | adapter-collected only | ✔ | link/unlink | – | – | partial |
| Reports | ✔ | ✔ | ✗ | ✗ | ✔ PDF export | done (MVP) |
| Incidents/Cases/Identities/Cloud/Controls/Risks | per 10.4.1 | ✔ | per 10.4.1 | – | 10.4.1 pass | not re-verified |
| Licensing | signed offline import (new) | ✔ summary | N/A | N/A | page added; API tests ✔ | partial — no browser run |
| Connectors, AI models | – | – | – | – | – | not touched |

## Automated
Backend 319 passed, 1 skipped, coverage 76 % (gate 75 %); frontend 95 passed (axe a11y suite included); ruff, black, tsc, eslint clean;
`pnpm audit --prod` and `pip-audit`: no known vulnerabilities; `alembic check` shows 8 foreign keys present in the migrated DB but not declared on the ORM models (DB stricter than models; no data risk, tracked).

## Northstar demo tenant (item 59–61)
`python -m cyberaudit.admin_cli seed-northstar` (requires `DEMO_ADMIN_PASSWORD`; refuses databases not named `*_demo`; idempotent).
Verified on PostgreSQL 16: 3 users (Administrator / Security Analyst / Read-only Viewer), 8 assets with relationships, 9 synthetic findings (all `simulated`, `unverified`, `[DEMO]`-labelled), 1 incident with timeline, 2 risks, 2 controls with assessments (gaps), evidence links, knowledge-graph nodes, report. Verified live: dashboard posture 51 % from real asset risk, Command Center, graph (7 nodes / 5 edges), analyst can read but not administer (403), viewer cannot create (403), Cyber AI incident analysis grounded (degraded deterministic mode, no model installed).
Demo reset = drop and recreate the dedicated demo database (never a customer database).

## Licensing (item 44)
`GET /license/summary`, `POST /license/import` (needs `license.manage`). A license is accepted only if its Ed25519 signature verifies against
`LICENSE_TRUSTED_PUBLIC_KEYS` configured on that server, it names the importing organization, and it is not expired. No keys configured = import refused (409).
Vendor tool: `scripts/licensing/issue_license.py` (`keygen`, `sign`) — the **evaluation entitlement** is simply a short-expiry signed license (e.g. `--days 30`) bound to one organization id; there is no universal license. Pricing/edition definitions were not changed.

## Assessment execution and job lifecycle (items 16, 17, 50) — live, PostgreSQL 16 + Dramatiq worker
Profile "Inventário básico" (consolidates known data; no traffic to third parties), analyst role, Northstar demo engagement (scope `10.40.0.0/16`):
| Case | Result |
|---|---|
| Target `10.40.0.10` (in scope) | job `queued` → worker → `completed` (100 %), `job.completed` notification created |
| Target `8.8.8.8` / `10.50.0.1` (outside scope) | `denied` by ScopePolicyEngine, never queued |
| Worker stopped, job created in scope | stays `queued` (durable); after the worker restarts → `COMPLETED` |
| Local URL target on a non-standard port (earlier) | `url_port_blocked` |
Not exercised: live network adapters (DNS/TLS/HTTP) against real third-party hosts — deliberately not run without an authorised target; Redis outage; mid-run worker crash; retry/cancel from the UI.
Note: denied requests return HTTP 201 with `status: "denied"` (the policy decision is the resource); clients must read `status`.

## Investor demo walk-through (Northstar tenant, browser, 1366×768; dashboard also 1920×1080)
| Scene | Result | Notes |
|---|---|---|
| 1 Command Center | PASS | posture 50.8 %, real top assets; "Serviços abertos 0 / Cobertura 0 %" are honest (no service/coverage data in the demo) |
| 2 Asset Intelligence | PASS (after fix) | list columns showed dashes (API/UI contract mismatch) → fixed |
| 3 Identity risk | PASS (after fix) | tenant had no identities → synthetic directory added (privileged/unowned/guest, MFA posture) |
| 4 Attack Graph | PASS | 7 nodes / 5 relations, search/filter/table view |
| 5 SOC incident | PASS | incident, timeline, evidence tab, cases |
| 6 Risk & GRC | PASS | controls with gaps, risk register, create forms |
| 7 Cyber AI | PASS (degraded mode) | deterministic, grounded answer now lists the facts used; no local model installed, stated on screen |
| 8 Reporting | PASS | executive report + PDF export (verified earlier) |
| 9 Multi-tenancy | PASS | verified earlier with two tenants (API) |
| 10 Operations | PASS (after fix) | Health Center showed hard-coded migration 0004 / version 4.0.0-dev → now real (0018) |
Also fixed: login divider said "acesso local de desenvolvimento".
Not done: scripted/recorded rehearsal with a presenter; cloud/Kubernetes scenes have no Northstar data.

## Backup / restore drill (item 51) — PostgreSQL 16, 30 008 assets + 60 009 findings
`pg_dump -Fc` 0.38 s (5.6 MB, 1 733 catalogue entries, SHA-256 recorded) → `pg_restore` into an isolated database 1.58 s.
Compared live vs restored: assets, findings, users, organizations, `alembic_version` (0018) and **135 RLS policies** — identical.
Reproduce on the server with `deploy/hetzner-evaluation/restore-test.sh` (writes only a throwaway database, drops it on exit).
Not tested: restore of the `uploads` volume, point-in-time recovery, restore timing at production size, off-host backup copy.
