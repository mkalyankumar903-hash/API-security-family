#!/usr/bin/env bash
# Phase14: disposable GitHub-hosted PostgreSQL16 logical backup and restore only.
set -euo pipefail
SOURCE_DB="${1:-api_family_phase13_pg_full}"
RESTORE_DB="api_family_phase14_dr_restore"
BAD_DB="api_family_phase14_dr_negative"
HOST="127.0.0.1"
PORT="55432"
ADMIN="postgres"
: "${PGPASSWORD:?disposable CI PostgreSQL admin password required}"
if [[ "${NODE_ENV:-}" != "test" || "${SYNTHETIC_AUTH_ENABLED:-}" != "true" ]]; then
  echo "PHASE14_DR_TEST_ONLY_AUTHORITY_REQUIRED"; exit 2
fi
if [[ ! "$SOURCE_DB" =~ ^api_family_phase13_pg_full$ ]]; then
  echo "PHASE14_DR_DISPOSABLE_SOURCE_ONLY"; exit 2
fi
DUMP="$(mktemp /tmp/api-family-phase14-dr.XXXXXXXX.dump)"
BAD="$(mktemp /tmp/api-family-phase14-bad.XXXXXXXX.dump)"
trap 'rm -f "$DUMP" "$BAD"' EXIT
admin_sql() {
  psql -X -v ON_ERROR_STOP=1 -h "$HOST" -p "$PORT" -U "$ADMIN" -d "$1" -Atc "$2"
}
fingerprint() {
  admin_sql "$1" "SELECT md5(COALESCE(string_agg(md5(row_to_json(t)::text), '|' ORDER BY row_to_json(t)::text),'')) FROM public.$2 t"
}
started="$(date +%s%3N)"
pg_dump -h "$HOST" -p "$PORT" -U "$ADMIN" -d "$SOURCE_DB" --format=custom --file="$DUMP" --no-comments
test -s "$DUMP"
psql -X -v ON_ERROR_STOP=1 -h "$HOST" -p "$PORT" -U "$ADMIN" -d postgres -q -c "CREATE DATABASE $RESTORE_DB;"
pg_restore -h "$HOST" -p "$PORT" -U "$ADMIN" -d "$RESTORE_DB" --no-owner --exit-on-error "$DUMP" >/dev/null
test "$(admin_sql "$RESTORE_DB" "SELECT count(*) FROM public.api_schema_migrations")" = "19"
# Compare EVERY persisted business and private-queue table, not six hand-picked
# tables. The same catalog-generated qualified identifiers are used in each DB.
# This preserves targets/history, inventories, findings, PT permits, worker leases,
# reports, usage/corrections, reconciliation and QA-only state byte-for-byte
# at the logical row level. A newly added table cannot silently escape the drill.
tables="$(admin_sql "$SOURCE_DB" "SELECT format('%I.%I',n.nspname,c.relname) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname IN ('public','api_queue') AND c.relkind='r' ORDER BY n.nspname,c.relname")"
restore_tables="$(admin_sql "$RESTORE_DB" "SELECT format('%I.%I',n.nspname,c.relname) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname IN ('public','api_queue') AND c.relkind='r' ORDER BY n.nspname,c.relname")"
if [[ -z "$tables" || "$tables" != "$restore_tables" ]]; then
 echo "PHASE14_DR_TABLE_SET_MISMATCH"; exit 1
fi
table_count=0
while IFS= read -r table; do
  [[ -z "$table" ]] && continue
  source_fp="$(admin_sql "$SOURCE_DB" "SELECT count(*)::text||':'||md5(COALESCE(string_agg(md5(row_to_json(t)::text),'|' ORDER BY row_to_json(t)::text),'')) FROM $table t")"
  restored_fp="$(admin_sql "$RESTORE_DB" "SELECT count(*)::text||':'||md5(COALESCE(string_agg(md5(row_to_json(t)::text),'|' ORDER BY row_to_json(t)::text),'')) FROM $table t")"
  if [[ "$source_fp" != "$restored_fp" ]]; then echo "PHASE14_DR_FINGERPRINT_MISMATCH $table"; exit 1; fi
  table_count=$((table_count+1))
done <<< "$tables"
if (( table_count < 35 )); then echo "PHASE14_DR_UNEXPECTED_SCHEMA_COVERAGE"; exit 1; fi
for database in "$SOURCE_DB" "$RESTORE_DB"; do
  # Catalog checks cover both RLS-enable and FORCE-RLS bits on every table.
  flags="$(admin_sql "$database" "SELECT string_agg(n.nspname||'.'||c.relname||':'||c.relrowsecurity||':'||c.relforcerowsecurity, '|' ORDER BY n.nspname,c.relname) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname IN ('public','api_queue') AND c.relkind='r'")"
  if [[ "$database" == "$SOURCE_DB" ]]; then source_flags="$flags"
  elif [[ "$flags" != "$source_flags" ]]; then echo "PHASE14_DR_RLS_CATALOG_MISMATCH"; exit 1
  fi
done
# PostgreSQL's restored FK constraints must continue matching the source.
source_constraints="$(admin_sql "$SOURCE_DB" "SELECT count(*) FROM pg_constraint WHERE contype IN ('f','u','p','c') AND connamespace IN (SELECT oid FROM pg_namespace WHERE nspname IN ('public','api_queue'))")"
restore_constraints="$(admin_sql "$RESTORE_DB" "SELECT count(*) FROM pg_constraint WHERE contype IN ('f','u','p','c') AND connamespace IN (SELECT oid FROM pg_namespace WHERE nspname IN ('public','api_queue'))")"
test "$source_constraints" = "$restore_constraints"
for table in api_v13_usage_ledger api_v13_qa_delivery api_v13_qa_delivery_events api_v13_qa_sink_receipts; do
  secure="$(admin_sql "$RESTORE_DB" "SELECT relrowsecurity AND relforcerowsecurity FROM pg_class WHERE oid='public.$table'::regclass")"
  test "$secure" = "t"
done
# Tenant context MUST NOT carry over from the original database, and an app
# principal must not inherit QA read authority after the restore.
if [[ "$(PGPASSWORD=api_family_dev psql -X -h "$HOST" -p "$PORT" -U api_family -d "$RESTORE_DB" -Atc 'SELECT count(*) FROM public.api_v13_usage_ledger')" != "0" ]]; then
  echo "PHASE14_DR_RLS_CONTEXT_BYPASS"; exit 1
fi
if PGPASSWORD=api_family_dev psql -X -h "$HOST" -p "$PORT" -U api_family -d "$RESTORE_DB" -Atc "SELECT count(*) FROM public.api_v13_qa_sink_receipts" >/dev/null 2>&1; then
  echo "PHASE14_DR_QA_PRIVILEGE_ESCALATION"; exit 1
fi
# A deliberately malformed archive must fail, never be accepted as an empty
# successful recovery. Operates on another disposable database only.
printf 'not-a-postgresql-custom-archive' > "$BAD"
psql -X -v ON_ERROR_STOP=1 -h "$HOST" -p "$PORT" -U "$ADMIN" -d postgres -q -c "CREATE DATABASE $BAD_DB;"
if pg_restore -h "$HOST" -p "$PORT" -U "$ADMIN" -d "$BAD_DB" --exit-on-error "$BAD" >/dev/null 2>&1; then
  echo "PHASE14_DR_MALFORMED_RESTORE_FALSE_SUCCESS"; exit 1
fi
ended="$(date +%s%3N)"
echo "PHASE14_SYNTHETIC_BACKUP_RESTORE_PASS elapsedMs=$((ended-started)) tableFingerprints=$table_count migrationCount=19 rls=FORCED qaPrivilege=DENIED malformedRestore=REJECTED"
