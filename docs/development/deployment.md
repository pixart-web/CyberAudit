# Deployment notes

Apply `alembic upgrade head` before starting API and workers. Include
`cyberaudit.domain_expansion_worker` in the Dramatiq module list. PostgreSQL and
Redis health checks must pass before the API becomes ready.

Production requires a supported secret manager and workload identity. Do not
use `development://demo-*`, local demo credentials or fixture adapters for
customer collection.

For hardened deployment, use `docker-compose.production.yml` or
`infrastructure/helm/cyberaudit`, provide immutable image digests and run
`make verify-production-config`. The Helm migration hook must complete before
API/worker rollout. `/health` is liveness; `/ready` verifies PostgreSQL and
Redis.
