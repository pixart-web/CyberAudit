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
