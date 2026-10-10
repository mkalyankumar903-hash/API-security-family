#!/usr/bin/env bash
# Real disposable PostgreSQL16 process stop/restart with migrations and persisted readback.
# Runs ONLY in test-only GitHub-hosted Actions. Does not touch the main CI postgres service.
set -euo pipefail
if [[ "${GITHUB_ACTIONS:-}" != "true" || "${NODE_ENV:-}" != "test" || "${SYNTHETIC_AUTH_ENABLED:-}" != "true" ]]; then
 echo "PHASE14_ISOLATED_GITHUB_CI_ONLY"; exit 2
fi
name="api-family-phase14-restart-${GITHUB_RUN_ID:-0}-$$"
port=55433
image="public.ecr.aws/docker/library/postgres:16"
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT
docker run -d --name "$name" -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=local_admin_only \
 -e POSTGRES_DB=api_family -p "127.0.0.1:$port:5432" "$image" >/dev/null
ready() {
 local i
 for ((i=0;i<45;i++));do
  if PGPASSWORD=local_admin_only pg_isready -h 127.0.0.1 -p "$port" -U postgres -d api_family >/dev/null 2>&1;then return 0;fi
  sleep 1
 done
 return 1
}
ready || { echo "PHASE14_FRESH_DATABASE_NEVER_READY"; exit 1; }
PGPASSWORD=local_admin_only psql -X -v ON_ERROR_STOP=1 -h 127.0.0.1 -p "$port" -U postgres -d api_family -f infrastructure/postgres-init/001_roles.sql >/dev/null
export DATABASE_URL="postgres://api_family:api_family_dev@127.0.0.1:$port/api_family"
export WORKER_DATABASE_URL="postgres://api_family_queue:api_family_worker_dev@127.0.0.1:$port/api_family"
export MIGRATION_DATABASE_URL="postgres://postgres:local_admin_only@127.0.0.1:$port/api_family"
npm run migrate >/dev/null
admin() { PGPASSWORD=local_admin_only psql -X -v ON_ERROR_STOP=1 -h 127.0.0.1 -p "$port" -U postgres -d api_family -Atc "$1"; }
test "$(admin "SELECT count(*) FROM api_schema_migrations")" = "19"
admin "CREATE TABLE public.phase14_disposable_recovery(id int PRIMARY KEY, marker text NOT NULL); INSERT INTO public.phase14_disposable_recovery(id,marker) VALUES(1,'SYNTHETIC_ONLY');" >/dev/null
before="$(admin "SELECT marker FROM public.phase14_disposable_recovery WHERE id=1")"
test "$before" = "SYNTHETIC_ONLY"
started="$(date +%s%3N)"
docker stop --time 4 "$name" >/dev/null
if PGCONNECT_TIMEOUT=2 PGPASSWORD=local_admin_only psql -X -h 127.0.0.1 -p "$port" -U postgres -d api_family -Atc "SELECT 1" >/dev/null 2>&1; then
 echo "PHASE14_DATABASE_STOP_DID_NOT_INTERRUPT_CONNECTION"; exit 1
fi
docker start "$name" >/dev/null
ready || { echo "PHASE14_DATABASE_RESTART_NEVER_READY"; exit 1; }
after="$(admin "SELECT marker FROM public.phase14_disposable_recovery WHERE id=1")"
test "$before" = "$after"
test "$(admin "SELECT count(*) FROM public.api_schema_migrations")" = "19"
test "$(admin "SELECT count(*) FROM pg_class WHERE relname='api_assessments'")" = "1"
test "$(admin "SELECT relrowsecurity AND relforcerowsecurity FROM pg_class WHERE oid='public.api_v13_usage_ledger'::regclass")" = "t"
elapsed="$(( $(date +%s%3N) - started ))"
echo "PHASE14_REAL_POSTGRES_SERVICE_RESTART_PASS elapsedMs=$elapsed migrationCount=19 dataPreserved=true forceRls=true network=loopback_only"
