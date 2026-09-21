# Secret management

Business tables store opaque `SecretReference` values, never resolved material. Provider interfaces
cover validation, resolution, metadata, health and rotation. Environment resolution is restricted
to development/test/demo and to an explicit variable allowlist.

Production accepts Vault, AWS Secrets Manager, Azure Key Vault, Google Secret Manager, Kubernetes
Secrets or Docker Secrets as configuration choices, but provider SDK resolution intentionally fails
closed until its workload identity is configured and tested. No fallback to environment values is
performed.

The redaction layer removes sensitive keys, bearer values, common assignment forms, credentials in
database URLs and private-key blocks. Logging code must pass structured values through this layer.
Token, password, evidence and connector payload bodies must never enter logs, metrics or telemetry.
