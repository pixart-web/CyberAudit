# Enterprise authentication

Production uses OpenID Connect Authorization Code with PKCE. Discovery metadata must match the
configured issuer; authorization, token and JWKS endpoints must remain below that issuer. ID tokens
require signature, issuer, audience, expiry, subject and nonce validation. Email-domain and group
allowlists may add restrictions.

OIDC state is tenant-namespaced, expires after ten minutes and is consumed atomically. JIT-created
accounts are pending by default and cannot authenticate until an administrator approves them.
Administrative group mapping is versioned and must never grant a role across organizations.

Local authentication exists for development and controlled recovery only. It uses Argon2, login
lockout, refresh-token rotation/reuse detection and the local password denylist. Production config
rejects local authentication.

TOTP factors store only opaque secret references. Recovery codes are random, hashed, single-use and
rotated as a complete set. WebAuthn is the preferred phishing-resistant factor for a subsequent
release; destructive policy decisions already distinguish phishing-resistant strength.

Browser sessions are random opaque values stored only as hashes server-side. They have idle and
absolute expiry, a per-user concurrency limit, SameSite cookies and independent CSRF material.
Logout and remote revocation invalidate server state.
