# Backup failure

1. Page the database owner and preserve the failed scheduler logs.
2. Check backup identity expiry, storage health, capacity and encryption recipient.
3. Never retain an unencrypted dump as a workaround.
4. Re-run a bounded backup, validate checksum and perform an isolated restore.
5. Update RPO exposure and readiness evidence.
