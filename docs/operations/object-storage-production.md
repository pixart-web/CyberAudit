# Production object storage

The S3 provider uses the SDK credential chain/workload identity. It does not
accept credentials from API requests. Object keys are opaque and rooted at
`organizations/<uuid>/<allowlisted-type>/`; cross-tenant keys are rejected
before SDK access.

Uploads set content length/type, SHA-256 metadata, server-side encryption and a
quarantine tag. Reads are bounded and verify the stored checksum. Presigned
download URLs expire in 60–900 seconds. Provider health uses `HeadBucket` and
exposes no private endpoint or credential data.

Production must configure bucket versioning, retention/lifecycle, deny-public
policy, TLS and an isolated workload identity. A real MinIO or cloud-S3
integration/retention exercise remains required evidence.
