# Runner failure

1. Stop new execution dispatch if cleanup or isolation fails.
2. Confirm the controller, immutable image digest and security profile.
3. Remove only the identified ephemeral execution through the controller.
4. Check for orphaned containers/Jobs and unexpected egress.
5. Resume after a success/failure/timeout/cancel cleanup test passes.
