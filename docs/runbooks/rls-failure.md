# RLS failure

1. Stop promotion and isolate the affected API pool.
2. Verify the connection assumes `cyberaudit_runtime`, not an owner/superuser.
3. Check migration head, enabled policies and transaction tenant context.
4. Run read/write isolation tests on an isolated clone.
5. Restore service only after policies and alerts are verified.
