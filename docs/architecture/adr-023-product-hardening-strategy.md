# ADR-023 — Product hardening and enterprise readiness

Status: accepted  
Base commit: `035f9df0a8b92f11d806f4951e60432414a0afd9`  
Branch: `codex/product-hardening-enterprise-readiness`

## Initial state and risks

CyberAudit has tenant-aware application queries, RBAC, audit logs, controlled
workers and migrations through `0009`. Authentication is development JWT,
sessions are refresh-token records, configuration has insecure defaults,
database connections use `NullPool`, storage is local-only, Enterprise
connectors are fixture/import-only and deployments lack CI, Helm, backup,
restore and release controls.

Primary risks are insecure production configuration, credential leakage,
cross-tenant task replay, insufficient session assurance, unbounded operational
growth, unavailable local storage, weak deployment defaults and claims of
readiness without measured evidence.

## Decisions

1. Add a fail-closed, typed production configuration gate.
2. Use opaque secret references through a closed `SecretProvider` registry and
   central recursive redaction.
3. Add provider-neutral OIDC Authorization Code + PKCE, local TOTP/recovery
   factors, server-side sessions and step-up state. SAML is deferred.
4. Centralize authorization decisions while preserving existing permission
   dependencies for API compatibility.
5. Add defense-in-depth RLS policies as an opt-in PostgreSQL deployment step;
   application tenant filters remain mandatory.
6. Define execution runners and connector SDK contracts. Only restricted local
   execution is enabled by default; production requires ephemeral Docker or
   Kubernetes runners.
7. Keep live connectors behind feature flags and provider allowlists. They are
   read-only and never silently replace fixtures.
8. Add object storage, lifecycle, licensing, telemetry and operational models
   in migration `0010`.
9. Provide hardened Compose/Helm, CI, SBOM, backup/restore and operational
   documentation. Results are reported only when executed.

## Rejected alternatives

- Storing resolved secrets in PostgreSQL or queues.
- Home-grown SAML parsing.
- Dynamic connector plugins or user-provided code.
- Enabling provider network access globally.
- Removing application tenant filters after enabling RLS.
- Mandatory online licensing or telemetry.
- Automatic destructive remediation and silent updates.

## Incremental plan and rollback

Each capability is feature-flagged and deny-by-default. Migration `0010` only
adds tables/indexes and can be downgraded while no hardening records are
required. Existing JWT endpoints and local filesystem storage remain available
in development. Rollback disables new flags, returns workers to prior modules
and deploys the previous application image; database rollback is optional
because additive tables are backward compatible.

## API, migration and operational impact

Existing `/api/v1` contracts remain. New authentication and operations routes
are additive. Production startup now rejects unsafe settings. Operators must
provide database/Redis TLS settings, non-default signing/encryption keys,
external object storage, secure proxy configuration and explicit authentication
mode. Migration execution must be singleton.

## Dependencies and limitations

OIDC uses standards implemented with HTTPX, PyJWT and cryptography. WebAuthn
requires an audited FIDO2 dependency and browser ceremony and is not claimed in
the initial increment. Provider SDK collectors need real tenant integration
tests. RLS, restore, HA, scale and chaos readiness remain unvalidated until
executed against representative infrastructure.
