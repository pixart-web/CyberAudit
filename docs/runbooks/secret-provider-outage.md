# Secret provider outage

1. Confirm Vault health and workload authentication without printing tokens.
2. Stop operations that need unresolved secrets; do not copy secrets to env vars.
3. Check seal state, policy, token expiry and network path with the Vault owner.
4. Restore availability, rotate affected credentials and verify consumers.
