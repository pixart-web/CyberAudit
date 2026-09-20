# OIDC validation

The OIDC client implements Authorization Code with PKCE S256, single-use state
and nonce, strict issuer/audience/signature validation and an HTTPS-only
production configuration. Discovery endpoints must remain below the configured
issuer and redirects are disabled. Email must be present and verified; inactive
accounts, unapproved domains, malformed or excessive groups and missing
mandatory groups are denied.

Only the explicit `CyberAudit-Viewer`, `CyberAudit-Analyst` and
`CyberAudit-Admin` mappings produce local roles. No IdP group maps to a global
super-administrator role. Provider secrets are resolved at the server boundary
through the configured secret manager and are never placed in state, sessions
or logs.

Protocol tests with signed representative tokens are automated. Validation
against Keycloak and a second real IdP is not available in the local workspace
and remains a production-readiness blocker until sanitized evidence is recorded.
