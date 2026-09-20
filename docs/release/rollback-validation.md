# Rollback validation

Application rollback redeploys the previously verified digests and Helm values.
Database rollback is not assumed: prefer forward-compatible expand/contract
migrations and a forward fix. Before any destructive downgrade, stop writers,
verify an encrypted backup, obtain approval and test the downgrade on an
isolated clone.

Validate API/web compatibility, worker queues, sessions, RLS and object
references after rollback. Record recovery time and the exact artifact digests.
