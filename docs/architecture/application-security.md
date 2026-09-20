# Application Security

Phase 5 adds a tenant-owned application domain above assets and engagements. An
`ApplicationAsset` groups APIs, repositories, releases, SBOMs, findings, scores,
exceptions and remediation while keeping `organization_id` authoritative.

The execution path remains API → RBAC → ScopePolicyEngine → JobOrchestrator →
Redis → worker revalidation → allowlisted adapter. Routers cannot invoke
adapters. Import endpoints parse bounded private files offline and audit upload,
preview, confirmation and decisions.

The first implementation is conservative: declared posture and synthetic
fixtures are supported; no repository is cloned and no submitted code or
container image is executed.
