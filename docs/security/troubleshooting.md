# Troubleshooting (Phase 10.4.18/48)

Diagnostics for local/on-prem installations. None of these steps ever
recommend disabling a security control (TLS verification, RLS, RBAC, secret
redaction) to "make an error go away" — if a fix here would require that,
it says so and stops instead.

## CyberAudit will not start

1. `./infrastructure/scripts/cyberaudit_launcher.sh status` — one line per
   service (name/status/health).
2. `./infrastructure/scripts/cyberaudit_launcher.sh logs` — tails every
   service's logs.
3. Missing `.env`: the launcher refuses to start and tells you to
   `cp .env.example .env` and set `JWT_SECRET`. This is intentional —
   CyberAudit does not run with a default secret outside development.

## Database unavailable

- `status` will show `postgres` as unhealthy. Check
  `docker compose logs postgres` for a corrupt volume or a port already
  bound by another Postgres instance on the host.
- Never point `DATABASE_URL` at a database whose schema was created by an
  older CyberAudit version without running `alembic upgrade head` first.

## AI runtime unavailable

- This is **not a fatal error**. `AI_RUNTIME_BACKEND=disabled` (the
  default) means CyberAudit is working exactly as designed — every
  AI/agent answer is deterministic. Check `/model-management` and the
  Cyber AI Workspace's "Local AI Runtime" panel; both show the real
  backend/health state (see ADR-026).
- If you explicitly configured `AI_RUNTIME_BACKEND=ollama` and it now
  shows unhealthy: confirm the Ollama server is actually running at
  `AI_RUNTIME_BASE_URL` and reachable from the API container (loopback
  binding means `127.0.0.1` inside the API container is *not* your host
  — use `host.docker.internal` or a shared Docker network).

## Model incompatible / insufficient RAM or VRAM

- `CapabilityRouter` will simply not select a model whose
  `ram_required_mb` exceeds detected available RAM — the answer degrades
  to the deterministic provider instead of failing. Check
  `/model-management`'s hardware panel against the model's stated
  requirement.
- There is no override to force-run an incompatible model; that is by
  design (section 12: "a low-spec machine should have slower or reduced
  AI capability, not a completely broken CyberAudit installation").

## Port conflict

- The launcher binds `8000`/`3000` to `127.0.0.1` only. If another local
  process already holds one of those ports, `docker compose up` will fail
  with a bind error naming the port — free it or edit the port mapping in
  `docker-compose.yml` (loopback-only) before retrying.

## Corrupted update / failed migration

- `/update-manager` only ever **validates** a `.caup` bundle
  (signature + checksums + version compatibility) — see ADR-029. It never
  applies one, so a corrupted bundle cannot corrupt a running
  installation; it is simply rejected with the specific reason shown in
  the UI.
- A failed `alembic upgrade head` leaves the database at its last
  successful revision; do not manually edit migration state. Re-run
  `alembic upgrade head` after fixing the underlying cause (check the
  error for a specific constraint/column conflict).

## Failed backup / failed restore

- CyberAudit's backup/restore scripts (`infrastructure/scripts/
  backup_postgres.sh`, `restore_drill.sh`) require `age` and produce a
  checksummed, encrypted artifact. A missing `BACKUP_ENCRYPTION_RECIPIENT`
  or `age` binary fails the backup outright rather than writing an
  unencrypted dump — this is intentional.
- Never treat a backup file's mere existence as proof it is restorable;
  run a restore drill against a disposable database before relying on it
  (see `docs/security/data-retention.md`).

## Collector disconnected

- The Phase 10.3 collector/agent architecture is interface-only in this
  phase (no shipped collector binary yet). "Disconnected" in the UI means
  no enrollment has happened, not a runtime fault.

## Offline mode

- See `docs/architecture/offline-mode.md`. `apps/api/tests/
  test_offline_mode.py` is the permanent regression test proving core
  functionality (auth, findings, evidence, reports, all ten Cyber AI
  agents, retrieval, and update-bundle validation) works with zero
  network access.

## Certificate problems

- The Docker Compose deployment does not terminate TLS itself yet (see
  ADR-030/`local-installation.md`); it is loopback-only HTTP by default.
  Do not add a browser exception for a self-signed certificate you did
  not generate yourself, and never disable certificate verification in a
  script or client configuration to work around a TLS error — that
  defeats the purpose of using TLS at all.
