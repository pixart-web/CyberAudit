# WebAuthn recovery

1. Verify identity using the approved out-of-band process and dual control.
2. Prefer another registered credential; never accept a public-key export.
3. Revoke the lost credential, sessions and recovery codes.
4. Register the replacement with user verification and record its audit event.
5. Investigate counter rollback or unexpected backup-state changes.
