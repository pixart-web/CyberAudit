# Restore procedure

1. Declare the incident, stop writers and select a verified encrypted backup.
2. Create an isolated `cyberaudit_restore_drill` database and private workspace.
3. Run the restore script, migration and application validation.
4. Verify RLS/tenant counts, authentication and object references.
5. Promote only with incident-lead approval; otherwise destroy the isolated clone.
