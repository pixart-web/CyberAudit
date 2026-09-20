# Production-like security test results

Status: **partially executed**.

Executed locally: automated security unit tests, signed representative OIDC
token validation, WebAuthn challenge replay protection, S3 tenant partition
tests and PostgreSQL runtime-role RLS denial of a cross-tenant update.

Not executed: real Keycloak/second-IdP login, browser authenticator ceremony,
Vault/MinIO policy tests, container/cluster runner escape tests, external DAST
or an independent penetration test. These remain explicit readiness blockers.
