# Product hardening architecture

Phase 10 turns the validated enterprise-domain build into an operable product baseline. It is
additive: existing APIs and data remain compatible, while production startup now fails closed when
identity, transport, secrets, storage or execution isolation are unsafe.

## Trust boundaries

1. The edge terminates TLS and forwards only allowlisted hosts to the web/API.
2. Authentication accepts local credentials only in controlled environments. Production requires
   OIDC Authorization Code + PKCE; state and nonce are single-use Redis records.
3. API authorization remains tenant-bound. `AuthorizationPolicyEngine` adds explainable,
   deny-by-default decisions and step-up requirements for sensitive operations.
4. Credentials remain opaque references until the connector boundary. Central redaction is applied
   to diagnostics, runner output and connector records.
5. Connectors are declared, versioned and read-only. URLs are restricted to exact HTTPS origins,
   redirects are disabled and responses are bounded.
6. Runner requests select a fixed internal operation. Arbitrary commands, environment variables,
   host paths, privileged containers and host sockets are outside the contract.
7. Objects are tenant-partitioned, quarantined and lifecycle-controlled. Filesystem storage is
   restricted to development; production requires an external provider.

## Deployment profiles

`development` and `test` allow SQLite, local storage and the restricted in-process runner.
`production`, `on_premises` and `ha` require PostgreSQL, TLS Redis, OIDC, an external secret
provider, external object storage and an ephemeral runner configuration.

The Helm chart deploys only application components. PostgreSQL, Redis, object storage, certificate
management and secret management are deliberate external dependencies. Image digests are required.

## Deliberate blockers

Cloud secret managers, cloud object stores and Docker/Kubernetes runner controllers expose
fail-closed contracts but do not yet resolve credentials or execute workloads. Provider-specific
live connector collection also remains blocked until credentials, provider sandboxes and contract
tests are available. These are not represented as production-ready capabilities.
