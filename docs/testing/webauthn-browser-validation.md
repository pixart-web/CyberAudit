# WebAuthn browser validation

Status: **blocked pending a trusted browser origin and operator validation**.

The automated run must use `https://cyberaudit.localhost:18443`, trust only the
laboratory CA generated under the ignored readiness runtime, and use Chromium's
virtual authenticator. TLS errors must never be bypassed. A physical security
key run is a separate, human-reviewed check.

## Required matrix

Record pass/fail, timestamp, browser version and sanitized trace for: registration,
authentication, invalid challenge, invalid origin, invalid RP ID, replay, sign
counter, revocation, multiple credentials, step-up and recovery. Verify that
traces contain no credential private key, full token, password or session cookie.

Store automated output under `artifacts/readiness/webauthn/`. A reviewer must
create `artifacts/readiness/reviews/webauthn.json` containing `approved: true`,
their non-automation identity and the SHA-256 of the summary artifact. The gate
rejects automation-only approval.

## Operator procedure

1. Start the production-like environment with `make readiness-up`.
2. Explicitly trust the lab CA for this test profile; do not install it as a
   system-wide root without security-owner approval.
3. Run the browser matrix against the exact HTTPS origin.
4. Repeat registration, authentication, step-up, revocation and recovery with a
   physical authenticator when one is available.
5. Inspect/redact evidence, calculate its checksum and sign the review record.
6. Run `make readiness-evidence` and `make readiness-gate`.

Removing the test profile and its lab CA trust is part of cleanup.
