# OIDC provider outage

1. Confirm the alert from two API replicas and check sanitized issuer health.
2. Do not enable local authentication in production.
3. Notify tenant administrators and preserve existing sessions within policy.
4. Escalate to the IdP owner; monitor discovery, JWKS and token endpoints.
5. After recovery, verify issuer/signature/nonce and revoke suspicious sessions.
6. Record timestamps and provider status without tokens or claims.
