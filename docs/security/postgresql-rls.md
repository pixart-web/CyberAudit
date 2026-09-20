# PostgreSQL row-level security

Migration `0011` enables RLS on every table containing `organization_id` and
creates a non-login, non-superuser, `NOBYPASSRLS` runtime role. Its policy
requires both reads and writes to match the transaction-local
`app.current_organization_id` setting. An absent setting returns no tenant rows.

Migrations `0012`–`0015` constrain organizations, indirect association tables,
worker bootstrap and system-owned registries. They also add a minimal
`SECURITY DEFINER` lookup that resolves only an active organization UUID from
its public login slug. The function has a fixed `search_path`, is revoked from
`PUBLIC` and exposes no tenant record.

The API derives tenant context from a verified token or that login bootstrap; it
never accepts an organization UUID from request data. Production database
connections automatically assume `cyberaudit_runtime`. Migration and backup
identities stay separate, time-bound and monitored. Application owners must not
be used as runtime identities because table owners can bypass RLS unless
`FORCE ROW LEVEL SECURITY` is used.

The local PostgreSQL integration test verified empty reads without context,
tenant-only reads with context and rejection of a cross-tenant update.
