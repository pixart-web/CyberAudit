# Backup validation

`infrastructure/scripts/backup_postgres.sh` creates a custom-format PostgreSQL
dump with owner/ACL data excluded, encrypts it with an age recipient, removes the
plaintext temporary and records SHA-256. The production scheduler must use a
separate least-privilege backup identity and upload the encrypted object to the
retained backup partition.

Evidence must include scheduler result, encrypted object metadata, checksum,
database version, migration head, duration and age without connection strings or
keys. A backup is not considered valid until a restore drill succeeds.
