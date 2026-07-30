# Production secret manager

The production implementation supports Vault KV v2 using references such as
`vault://secret/apps/cyberaudit?version=7#client_secret`. Mount, path, version and
field are parsed against a restrictive grammar. Vault must use HTTPS, redirects
are disabled and network timeouts are bounded.

The Vault token is read from the deployment-owned fixed token file. API clients
cannot submit tokens, endpoints or filesystem paths. Secret values are resolved
only at their consuming server boundary and are never returned by metadata or
health endpoints. Rotation is deliberately delegated to an approved provider
workflow: CyberAudit does not accept replacement secret values.

A real Vault health, policy, expiry and rotation exercise is still required
before the readiness check may pass.
