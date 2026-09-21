# Dead-letter queue

1. Inspect sanitized queue, error code, attempts and opaque payload reference.
2. Resolve the dependency or schema/feature mismatch before replay.
3. Obtain the required permission and WebAuthn step-up.
4. Replay one message and verify idempotency before any bounded batch.
5. Acknowledge or discard only with documented impact and audit evidence.
