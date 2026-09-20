#!/bin/sh
set -eu

: "${DATABASE_URL:?DATABASE_URL is required}"
: "${BACKUP_DIRECTORY:?BACKUP_DIRECTORY is required}"
: "${BACKUP_ENCRYPTION_RECIPIENT:?BACKUP_ENCRYPTION_RECIPIENT is required}"

case "$BACKUP_DIRECTORY" in
  /|""|*..*) echo "Unsafe BACKUP_DIRECTORY" >&2; exit 2 ;;
esac

umask 077
mkdir -p "$BACKUP_DIRECTORY"
timestamp=$(date -u +%Y%m%dT%H%M%SZ)
target="$BACKUP_DIRECTORY/cyberaudit-$timestamp.dump"
encrypted="$target.age"

pg_dump --format=custom --no-owner --no-acl --dbname="$DATABASE_URL" --file="$target"
age --recipient "$BACKUP_ENCRYPTION_RECIPIENT" --output "$encrypted" "$target"
shred -u "$target" 2>/dev/null || rm -f "$target"
sha256sum "$encrypted" > "$encrypted.sha256"
echo "Encrypted backup created: $encrypted"
