# Redis failover

1. Pause dispatch while confirming failover/quorum state.
2. Promote through the managed Redis mechanism; do not flush queues.
3. Verify OIDC/WebAuthn single-use state, rate limits and queue idempotency.
4. Reconcile in-flight jobs and move poison messages to the DLQ.
