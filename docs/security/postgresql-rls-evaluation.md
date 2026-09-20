# PostgreSQL row-level security evaluation

All business queries currently derive `organization_id` from authenticated context and enforce it
in application repositories. Tests cover cross-tenant access. PostgreSQL RLS was evaluated as a
valuable second boundary, but enabling it partially would break unauthenticated identity lookup and
workers that currently receive only record identifiers.

RLS is therefore a documented production blocker, not a cosmetic policy:

1. split migration/owner and runtime database roles;
2. include `organization_id` in every worker message;
3. set a transaction-local `app.organization_id` before the first query;
4. introduce SECURITY DEFINER identity lookup limited to normalized email/provider;
5. add policies to all tenant tables and `FORCE ROW LEVEL SECURITY`;
6. run API, worker, migration, backup and cross-tenant suites under the non-owner runtime role;
7. only then enable policies in production.

This release does not claim database-enforced RLS. Application isolation remains mandatory and
tested; the risk and rollout sequence are explicit in the readiness checklist.
