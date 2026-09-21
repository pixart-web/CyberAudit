# Restore validation

The restore drill accepts only an encrypted age backup and only a database URL
whose database is explicitly named `cyberaudit_restore_drill`. It decrypts into
a private temporary directory, restores with `--exit-on-error` and verifies the
Alembic version.

The operator must additionally start the API against the isolated database,
verify tenant/RLS counts, authenticate, read representative assets and compare
checksums. Record RTO, RPO, duration and sanitized results. Never restore over a
running production database.
