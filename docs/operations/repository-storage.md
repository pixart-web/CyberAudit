# Repository Storage

Phase 5 does not persist repository working trees. Uploaded OpenAPI/SBOM files use
random private storage keys, mode 0600, size limits and SHA-256. Do not place
uploads below the frontend public directory. S3 migration must preserve private
buckets, tenant prefixes, encryption, short-lived access and audit events.
