#!/bin/sh
# Local-first workstation launcher (Phase 10.3.8).
#
# Supervises CyberAudit via the existing docker-compose.yml: start, stop,
# status and logs. It never exposes CyberAudit beyond loopback -- the base
# compose file already binds the API and web ports to 127.0.0.1 only; use
# docker-compose.remote.yml to opt in to LAN access explicitly.
#
# This wraps Docker Compose; it does not replace it with a separate service
# manager, and it does not install anything itself. See
# docs/architecture/local-installation.md for what remains architecture-only
# (native Windows/macOS/Linux installers).
set -eu

cd "$(dirname "$0")/../.."

usage() {
  echo "Usage: $0 {up|down|status|logs|restart}" >&2
  exit 2
}

compose() {
  if docker compose version >/dev/null 2>&1; then
    docker compose "$@"
  elif command -v docker-compose >/dev/null 2>&1; then
    docker-compose "$@"
  else
    echo "Neither 'docker compose' nor 'docker-compose' is available." >&2
    exit 1
  fi
}

require_docker() {
  if ! command -v docker >/dev/null 2>&1; then
    echo "Docker is required. Install Docker Desktop (macOS/Windows) or Docker Engine (Linux)." >&2
    exit 1
  fi
}

require_env_file() {
  if [ ! -f .env ]; then
    echo ".env is missing. Run: cp .env.example .env, then set JWT_SECRET before continuing." >&2
    exit 1
  fi
}

cmd_status() {
  compose ps --format '{{.Name}}\t{{.Status}}\t{{.Health}}'
}

cmd_up() {
  require_docker
  require_env_file
  echo "Starting CyberAudit (loopback-only: not exposed to the LAN by default)..."
  compose up -d

  echo "Waiting for services to report healthy..."
  attempt=0
  max_attempts=60
  while [ "$attempt" -lt "$max_attempts" ]; do
    unhealthy=$(compose ps --format '{{.Name}} {{.Health}}' 2>/dev/null \
      | awk '$2 != "healthy" && $2 != "" {print $1}')
    if [ -z "$unhealthy" ]; then
      echo "All services are healthy."
      echo "CyberAudit is ready: http://127.0.0.1:3000"
      return 0
    fi
    attempt=$((attempt + 1))
    sleep 2
  done

  echo "Timed out waiting for services to become healthy." >&2
  echo "Diagnostics:" >&2
  cmd_status >&2
  echo "Run '$0 logs' for details." >&2
  return 1
}

cmd_down() {
  compose down
}

cmd_restart() {
  cmd_down
  cmd_up
}

cmd_logs() {
  compose logs --follow --tail=200
}

case "${1:-up}" in
  up) cmd_up ;;
  down) cmd_down ;;
  status) cmd_status ;;
  restart) cmd_restart ;;
  logs) cmd_logs ;;
  *) usage ;;
esac
