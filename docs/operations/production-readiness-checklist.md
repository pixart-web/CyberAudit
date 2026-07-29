# Production readiness checklist

Evidence date: 2026-07-29. `ready` means verified in this repository/local environment; `blocked`
means external infrastructure or an unfinished control is required.

| Category | Status | Owner | Evidence | Date | Notes | Blocking |
|---|---|---|---|---|---|---|
| Security | partial | Security Engineering | 153 backend tests; threat model | 2026-07-29 | Critical new primitives tested | External penetration review |
| Authentication | partial | IAM | OIDC/PKCE code and unit tests | 2026-07-29 | Real IdP interoperability not run | Yes |
| Authorization | partial | Platform Security | AuthorizationPolicyEngine tests | 2026-07-29 | Existing dependencies not fully consolidated | Yes |
| Tenancy | partial | Data Security | Existing cross-tenant suite; RLS evaluation | 2026-07-29 | PostgreSQL RLS not enabled | Yes |
| Secrets | partial | Platform Security | SecretProvider/redaction tests | 2026-07-29 | External providers fail closed | Yes |
| Storage | partial | Platform | upload/storage tests | 2026-07-29 | Cloud SDK integrations absent | Yes |
| Database | ready-local | DBA | upgrade 0009→0010 passed | 2026-07-29 | Production roles/TLS/PITR external | Yes |
| Queues | partial | Platform | worker started; Redis chaos smoke | 2026-07-29 | Dedicated DLQ absent | Yes |
| Workers | partial | Platform | Dramatiq worker and metrics started | 2026-07-29 | Ephemeral controller absent | Yes |
| Networking | partial | Platform Security | exact-origin SDK tests; NetworkPolicy | 2026-07-29 | CNI/provider validation absent | Yes |
| TLS | partial | SRE | production validator, ingress TLS | 2026-07-29 | Certificate issuance external | Yes |
| Backups | blocked | DBA | encrypted scripts syntax checked | 2026-07-29 | `age` unavailable; backup not executed | Yes |
| Restore | blocked | DBA | isolated restore script syntax checked | 2026-07-29 | No encrypted backup; drill not executed | Yes |
| HA | documented | SRE | Helm replicas/PDB/HPA and DR docs | 2026-07-29 | Multi-node test absent | Yes |
| DR | documented | SRE | disaster recovery runbook | 2026-07-29 | RPO/RTO not measured | Yes |
| Observability | partial | SRE | metrics, structured logs, trace context, alert rules | 2026-07-29 | Exporter/alert receiver external | Yes |
| Performance | ready-local | Performance | 200/20 and 1000/50 localhost runs | 2026-07-29 | Not representative of production | No |
| Testing | ready-local | QA | backend 153; frontend 16; build 92 routes | 2026-07-29 | Coverage is 64%, below 75% | Yes |
| Supply Chain | partial | Release Engineering | GitHub PR CI: backend/frontend/migrations/secret scan passed | 2026-07-29 | Tagged SBOM/provenance/signing release not run | Yes |
| Licensing | ready-local | Product | Ed25519 offline license tests | 2026-07-29 | Online provider absent by design | No |
| Updates | documented | Release Engineering | upgrade/rollback guide | 2026-07-29 | Staged production rehearsal absent | Yes |
| Documentation | ready | Engineering | architecture/security/operations docs | 2026-07-29 | Provider-specific guides remain | No |
| Operations | partial | SRE | settings UI, runbooks, health/readiness | 2026-07-29 | External monitors/on-call integration | Yes |

Overall decision: **not production-ready**. The implementation is a tested local hardening baseline;
items marked blocking must be closed with real provider and production-like infrastructure.
