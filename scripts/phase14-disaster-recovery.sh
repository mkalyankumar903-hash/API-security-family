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
for table in api_assessments api_v13_usage_ledger api_v13_usage_corrections api_v13_feature_sources api_v13_outbox api_v13_qa_sink_receipts; do
  source_fp="$(fingerprint "$SOURCE_DB" "$table")"
  restored_fp="$(fingerprint "$RESTORE_DB" "$table")"
  if [[ "$source_fp" != "$restored_fp" ]]; then echo "PHASE14_DR_FINGERPRINT_MISMATCH $table"; exit 1; fi
done
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
echo "PHASE14_SYNTHETIC_BACKUP_RESTORE_PASS elapsedMs=$((ended-started)) tableFingerprints=6 migrationCount=19 rls=FORCED qaPrivilege=DENIED malformedRestore=REJECTED"
