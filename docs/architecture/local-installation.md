# Local installation and deployment modes (Phase 10.3.8)

This page states, honestly, what is and is not ready today. Nothing here is
claimed production-ready unless it has actually been built and run.

## Docker Compose (real, tested)

`docker-compose.yml` is the supported way to run CyberAudit today, on any
workstation or server with Docker installed (macOS, Linux, Windows via
Docker Desktop/WSL2).

```bash
cp .env.example .env
# set JWT_SECRET before the first start
./infrastructure/scripts/cyberaudit_launcher.sh up
```

`cyberaudit_launcher.sh` wraps `docker compose` (or the standalone
`docker-compose`, whichever is present) with the diagnostics section 26
asks for:

- `up` — starts every service and polls each container's own health check
  until all report healthy, or times out with a diagnostics dump;
- `status` — one line per service: name, status, health;
- `logs` — follows every service's logs;
- `restart` — `down` then `up`;
- `down` — stops everything.

**Loopback by default.** `docker-compose.yml` binds the API (`8000`) and web
(`3000`) ports to `127.0.0.1` only — nothing on the container host's LAN can
reach CyberAudit unless an administrator explicitly opts in with
`docker-compose.remote.yml`:

```bash
docker compose -f docker-compose.yml -f docker-compose.remote.yml up -d
```

**What was verified in this phase:** the compose file (base and merged with
the remote override) parses and resolves correctly
(`docker compose config`/`docker-compose config`), and the launcher
script's guard clauses (missing Docker, missing `.env`) fail cleanly with an
actionable message. A full image build and end-to-end boot was not run in
this session (multi-minute build, requires network access to base images);
that is the next verification step before calling this mode
production-ready.

**Not yet implemented:** local TLS termination (an `infrastructure/nginx`
reverse proxy is still an empty placeholder — see that directory's
`README.md`), and a data-directory layout separating config/database/
evidence/models/logs/backups on the host filesystem (section 27). Until
then, treat this mode as *development/pilot*, not a hardened production
appliance.

## Native installers (architecture only — not built)

Section 24 asks for `CyberAudit-Setup-x64.exe` (Windows), `.deb`/`.rpm`
(Linux) and `.pkg`/`.dmg` (macOS). **None of these exist.** Building and
testing a real installer for each platform is a substantial, platform-
specific undertaking (code signing, service registration, upgrade/uninstall
flows) that was not attempted here, to avoid producing something that only
*looks* like an installer.

The realistic path, given the Docker Compose baseline above, is a thin
per-OS wrapper around it:

- **Windows**: a signed installer that bundles/checks for Docker Desktop
  (or WSL2), lays down the compose files and `.env` template, registers a
  Start Menu shortcut that runs the equivalent of `cyberaudit_launcher.sh
  up`, and opens the default browser at `http://127.0.0.1:3000`.
- **Linux**: a `.deb`/`.rpm` that installs the compose files under
  `/opt/cyberaudit`, a systemd unit that runs `docker compose up` at boot
  (guarded by `Requires=docker.service`), and a CLI entrypoint
  (`cyberaudit up|down|status|logs`, i.e. this same launcher script).
  Packaging control files were not produced in this phase.
- **macOS**: a `.pkg` following the same shape as Linux, using a LaunchAgent
  instead of systemd.

Enterprise VM/appliance, Kubernetes/Helm charts and a private-infrastructure
deployment guide are similarly **not yet produced**.

## Data directories (partially implemented)

`UPLOAD_DIR` already separates evidence uploads from the rest of the
filesystem (see `.env.example`), with restrictive permissions enforced by
`cyberaudit/storage.py`. A full split of configuration, database, models
(ADR-026's model registry), knowledge packs, logs, temporary data and
backups into explicit per-OS application-data directories has not been
implemented; today the database lives in the `postgres_data` Docker volume
and everything else is either in-container or under the repository root.

## Service supervision beyond Docker Compose

Compose's own `depends_on`/health checks already provide restart-on-crash
and startup ordering for `postgres` → `redis` → `api`/`worker` → `web`. A
native OS-level supervisor (systemd/launchd) is only meaningful once a
native installer exists (see above); Docker Compose already fulfills that
role for the supported deployment mode today.
