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
| Clients | ✔ | ✔ | ✗ no PATCH | API `DELETE` only, no UI | ✔ create/list | partial |
| Engagements | ✔ (UI pre-existing) | ✔ | status only | – | not re-run | partial |
| Scope / targets | ✔ | ✔ | ✗ | ✗ | form added, API ✔ | partial |
| Assets | ✔ | ✔ | ✗ no PATCH in main API | ✗ | form added, API ✔ | partial |
| Jobs / imports | ✔ (API) | ✔ | cancel/retry (API) | – | import UI missing | partial |
| Findings | via import/job only | ✔ | ✗ | ✗ | list ✔ | partial |
| Evidence | adapter-collected only | ✔ | link/unlink | – | – | partial |
| Reports | ✔ | ✔ | ✗ | ✗ | ✔ PDF export | done (MVP) |
| Incidents/Cases/Identities/Cloud/Controls/Risks | per 10.4.1 | ✔ | per 10.4.1 | – | 10.4.1 pass | not re-verified |
| Licensing, Connectors, AI models | – | – | – | – | – | not touched |

## Automated
Backend 319 passed, 1 skipped, coverage 76 % (gate 75 %); frontend 95 passed (axe a11y suite included); ruff, black, tsc, eslint clean;
`pnpm audit --prod` and `pip-audit`: no known vulnerabilities; `alembic check` shows 8 foreign keys present in the migrated DB but not declared on the ORM models (DB stricter than models; no data risk, tracked).
