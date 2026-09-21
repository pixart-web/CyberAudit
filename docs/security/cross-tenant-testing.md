# Cross-tenant testing

Cross-tenant tests create two unrelated organizations and exercise API filters,
service queries, object keys, WebAuthn challenges, dead-letter messages and the
PostgreSQL RLS boundary. Tests must cover read, create, update and delete paths,
including guessed identifiers.

The opt-in database suite uses only a localhost PostgreSQL URL supplied through
`CYBERAUDIT_RLS_TEST_DATABASE_URL`, switches to the restricted runtime role and
rolls back its transaction. CI must provision an isolated database and run this
suite. Any unexpected row or successful foreign write is release-blocking and
triggers the cross-tenant alert runbook.
