#!/bin/sh
set -eu

: "${RESTORE_DATABASE_URL:?RESTORE_DATABASE_URL is required}"
: "${BACKUP_FILE:?BACKUP_FILE is required}"
: "${BACKUP_IDENTITY_FILE:?BACKUP_IDENTITY_FILE is required}"

case "$RESTORE_DATABASE_URL" in
  *cyberaudit_restore_drill*) ;;
  *) echo "Restore is restricted to an isolated cyberaudit_restore_drill database" >&2; exit 2 ;;
esac
case "$BACKUP_FILE" in
  *.age) ;;
  *) echo "Only encrypted .age backups are accepted" >&2; exit 2 ;;
esac

temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT INT TERM
age --decrypt --identity "$BACKUP_IDENTITY_FILE" --output "$temporary/restore.dump" "$BACKUP_FILE"
pg_restore --exit-on-error --clean --if-exists --no-owner --no-acl \
  --dbname="$RESTORE_DATABASE_URL" "$temporary/restore.dump"
psql "$RESTORE_DATABASE_URL" --set=ON_ERROR_STOP=1 \
  --command="SELECT count(*) AS migration_rows FROM alembic_version;"
echo "Isolated restore drill completed; application verification is still required."
