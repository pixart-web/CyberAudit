# Backup and restore

`infrastructure/scripts/backup_postgres.sh` creates a PostgreSQL custom-format dump, encrypts it
with an operator-supplied age recipient, removes the plaintext and writes a SHA-256 manifest.
Backups must be copied to versioned immutable object storage by the platform operator.

`infrastructure/scripts/restore_drill.sh` accepts only encrypted backups and refuses any database URL
that does not identify `cyberaudit_restore_drill`. It restores with `--clean --if-exists`, checks the
migration table and leaves application-level verification to the operator.

Required evidence for each production drill:

- backup record, encryption/key version, manifest and immutable-storage retention;
- restore start/end, isolated destination and approver;
- migration, tenant counts, login, policy evaluation and representative object download checks;
- measured RPO/RTO, errors, remediation owner and next drill date.

No backup or restore is considered verified merely because a command returned successfully.
