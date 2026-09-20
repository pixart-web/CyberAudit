# Operational runbooks

## Queue backlog

Check worker health, queue age and retry rate. Pause new schedules before scaling workers. Never
requeue a job by editing its status; use the orchestrator's idempotent retry operation.

## Redis unavailable

Keep API reads available where safe, reject new asynchronous work, and do not silently switch to an
in-memory production queue. Restore Redis/TLS connectivity and reconcile queued database records.

## PostgreSQL unavailable

Remove unhealthy instances from service, stop workers to avoid retry storms, preserve WAL/managed
service evidence and execute the documented DR process if recovery exceeds the objective.

## OIDC unavailable

Do not enable local authentication as an emergency shortcut. Preserve existing valid sessions until
their normal expiry, communicate the identity-provider incident and follow the controlled break-glass
procedure maintained outside this repository.

## Secret exposure

Revoke/rotate at the provider, terminate affected sessions/jobs, inspect redacted audit trails,
invalidate cached references and conduct a scoped incident review. Never paste the secret into an
issue or log.

## Failed migration

Stop the rollout, retain migration output, verify whether the transaction committed, and restore or
apply the migration-specific forward fix. Downgrade is used only after confirming it is data-safe.
