# Rollback

1. Freeze writes and verify the last known-good signed digests.
2. Roll back stateless components through the deployment controller.
3. Prefer a forward database fix; require backup and approval for a downgrade.
4. Validate sessions, queues, RLS, objects and audit continuity.
5. Record recovery time, data impact and follow-up actions.
