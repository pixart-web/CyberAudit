# Releases, upgrades and rollback

Release tags follow semantic versioning. The release workflow builds API/web images, requests
BuildKit provenance and SBOM attestations, pushes immutable digests and keyless-signs each digest.
The workflow must pass branch protection and security CI before a tag is created.

## Upgrade

1. read release notes and migration compatibility;
2. take and verify an encrypted backup;
3. deploy the digest to staging and run the pre-upgrade migration job;
4. execute login, tenant-isolation, policy, job and object-access smoke checks;
5. deploy canary API/web replicas, then workers;
6. monitor errors, queue latency and SLOs before completing rollout.

## Rollback

Application images may roll back to the prior digest. Database rollback is not assumed safe:
prefer a forward migration fix. If a release made an irreversible data change, restore into an
isolated environment, validate it, then perform the approved DR switch. Never run Alembic downgrade
automatically.

Feature flags default off and may isolate incomplete behavior, but cannot bypass authentication,
authorization, tenant, scope or audit controls.
