# Hetzner evaluation runbook

Prepared and validated locally (compose syntax, scripts, full journey on PostgreSQL 16). **Not yet executed on the Hetzner host.**

## 0. Read-only inspection of the current server (before touching anything)
```bash
cd /srv/nodera/applications/cyberaudit
docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}'
docker inspect --format '{{.Name}} {{.Image}} {{index .Config.Labels "org.opencontainers.image.revision"}}' $(docker ps -q)
docker exec <postgres> psql -U <user> <db> -c 'select * from alembic_version'
docker exec <postgres> psql -U <user> <db> -c 'select email,status from users'      # who can log in?
docker network ls | grep -i traefik; df -h /var/lib/docker
```

## 1. First deployment
1. `cp .env.example .env && chmod 600 .env`; fill secrets (`openssl rand -base64 36`). Set `BOOTSTRAP_TOKEN` only for the first run.
2. Review the diff of the release SHA; then `./deploy.sh <git-sha>`. It: checks disk/secrets → `pg_dump` + catalogue verification → builds images from that exact commit (`NEXT_PUBLIC_API_URL=https://$CANONICAL_HOST/api/v1`) → migrations → up → `smoke-test.sh`.
3. Open `https://<host>/setup`, enter the token, create organization + administrator. **Then remove `BOOTSTRAP_TOKEN` from `.env` and `docker compose up -d`.** `/setup` answers 403 afterwards (also while any user exists).
4. Existing database that already has users (e.g. the current install): bootstrap is intentionally unavailable. Instead:
   ```bash
   docker compose exec api python -m cyberaudit.admin_cli ensure-rbac
   docker compose exec api python -m cyberaudit.admin_cli provision-catalog --org <slug>
   docker compose exec -e NEW_PASSWORD=... api python -m cyberaudit.admin_cli rotate-password --email <admin>
   ```
   **If the demo seed ever ran, rotate `admin@cyberaudit.local` immediately** (default password was `ChangeMe123!`).

## 2. Backup / restore test (never restore over live data)
```bash
docker compose exec -T postgres pg_dump -U cyberaudit -Fc cyberaudit > backups/manual.dump
docker run -d --name restore-test -e POSTGRES_PASSWORD=t -p 127.0.0.1:55998:5432 postgres:16-alpine
docker exec -i restore-test pg_restore -U postgres -d postgres --create < backups/manual.dump
docker exec restore-test psql -U postgres cyberaudit -c 'select count(*) from users'; docker rm -f restore-test
```
Also back up the `uploads` volume (authorization PDFs, imports).

## 3. Rollback
`deploy.sh` stores `releases/<stamp>.rollback.env` and the pre-migration dump. Application rollback = point `CYBERAUDIT_*_IMAGE` back and `up -d` (migrations are additive; do not downgrade the schema without a reviewed plan). Data rollback = restore the dump into a **new** database, verify, then switch.

## 4. Post-deploy acceptance
`./smoke-test.sh https://<host>` (read-only) then the journey in `docs/operations/commercial-readiness-acceptance.md`.

## Known limits of this profile
Local auth enabled (no IdP), MFA/WebAuthn/OIDC not enforced, `RLS_REQUIRED=false` (the strict RLS runtime role is part of the production profile), no HA, no external object storage. This is **evaluation**, not production — see ProductionReadinessGate.
