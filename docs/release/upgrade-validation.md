# Upgrade validation

Start from the latest supported release with representative tenant data. Create
and verify a backup, deploy the candidate API/web/worker digests, apply Alembic
migrations once, and validate authentication, sessions, RLS, queues, findings,
object access and adapters. Observe mixed-version compatibility only for the
documented rolling window.

Record duration, migration head, data invariants and errors. Any destructive
migration requires an explicit expand/migrate/contract plan and blocks automatic
promotion.
