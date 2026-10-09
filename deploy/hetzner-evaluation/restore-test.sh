#!/usr/bin/env bash
# Non-destructive restore drill: dump the live DB, restore into a THROWAWAY database in the same
# PostgreSQL container, compare row counts / schema revision / RLS policy count, then drop it.
# Never touches the live database's data.
set -euo pipefail
cd "$(dirname "$0")"
if docker compose version >/dev/null 2>&1; then DC="docker compose"; else DC="docker-compose"; fi
mkdir -p backups
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
DUMP="backups/drill-$STAMP.dump"
TMPDB="restore_drill_$(date +%s)"
psql_live() { $DC exec -T postgres psql -U cyberaudit -d "$1" -tAc "$2"; }

t0=$(date +%s)
$DC exec -T postgres pg_dump -U cyberaudit -Fc cyberaudit > "$DUMP"
sha256sum "$DUMP" > "$DUMP.sha256"
t1=$(date +%s)
$DC exec -T postgres pg_restore -l < "$DUMP" > /dev/null
$DC exec -T postgres psql -U cyberaudit -d postgres -c "create database $TMPDB" > /dev/null
trap '$DC exec -T postgres psql -U cyberaudit -d postgres -c "drop database if exists $TMPDB" >/dev/null 2>&1 || true' EXIT
$DC exec -T postgres pg_restore -U cyberaudit -d "$TMPDB" --no-owner < "$DUMP" > /dev/null
t2=$(date +%s)

fail=0
for q in "select count(*) from users" "select count(*) from organizations" "select count(*) from findings" \
         "select count(*) from audit_logs" "select version_num from alembic_version" "select count(*) from pg_policies"; do
  a=$(psql_live cyberaudit "$q"); b=$(psql_live "$TMPDB" "$q")
  if [[ "$a" == "$b" ]]; then echo "PASS  $q -> $a"; else echo "FAIL  $q live=$a restored=$b"; fail=1; fi
done
echo "dump=$((t1-t0))s restore=$((t2-t1))s size=$(du -h "$DUMP" | cut -f1) file=$DUMP"
exit $fail
