# Enterprise permissions

Connector permissions separate read, manage, execute and credential management.
Domain permissions separate inventory, posture, risk, graph and Zero Trust
evaluation:

`enterprise_connectors.*`, `enterprise_credentials.manage`, `identity.*`,
`active_directory.read`, `entra.read`, `saas.read`, `cloud.*`,
`kubernetes.*`, `container_runtime.*`, `endpoints.*`, `mobile.*`,
`zero_trust.*` and `enterprise_exports.create`.

Administrator receives all permissions. Auditor excludes credentials and
exports. Reviewer is read-only. Client sees only approved posture summaries.

Product hardening adds:

`authentication_providers.read/manage`, `sessions.read/manage`, `mfa.manage`,
`feature_flags.read/manage`, `license.read/manage`, `telemetry.read/manage`,
`operations.read`, `backups.read/manage` and `restores.read/manage`.

Sensitive management decisions require step-up strength in the central policy.
The development seed grants these permissions only to Administrator.
