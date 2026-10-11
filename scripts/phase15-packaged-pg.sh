#!/usr/bin/env bash
set -euo pipefail
# Disposable GitHub runner only. Never points at customer, Host or populated production DB.
test "${GITHUB_ACTIONS:-}" = "true"
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT
psql -h 127.0.0.1 -p 55432 -U postgres -d postgres -v ON_ERROR_STOP=1 -c "CREATE DATABASE api_family_phase15_packaged;"
psql -h 127.0.0.1 -p 55432 -U postgres -d api_family_phase15_packaged -v ON_ERROR_STOP=1 -c "GRANT CONNECT ON DATABASE api_family_phase15_packaged TO api_family, api_family_queue, api_family_qa_ci; GRANT USAGE,CREATE ON SCHEMA public TO api_family;"
tar -xzf build/phase15-release/api-service.tar.gz -C "$scratch"
(cd "$scratch" && npm ci --omit=dev --ignore-scripts --no-audit --no-fund)
export DATABASE_URL="postgres://api_family:api_family_dev@127.0.0.1:55432/api_family_phase15_packaged"
export WORKER_DATABASE_URL="postgres://api_family_queue:api_family_worker_dev@127.0.0.1:55432/api_family_phase15_packaged"
export MIGRATION_DATABASE_URL="postgres://postgres:local_admin_only@127.0.0.1:55432/api_family_phase15_packaged"
(cd "$scratch" && node packages/database/src/migrate.js)
(cd "$scratch" && node packages/database/src/migrate.js)
(cd "$scratch" && node packages/database/src/migrate.js) &
a=$!
(cd "$scratch" && node packages/database/src/migrate.js) &
b=$!
wait "$a"
wait "$b"
versions="$(psql -h 127.0.0.1 -p 55432 -U postgres -d api_family_phase15_packaged -At -c 'SELECT count(*) FROM public.api_schema_migrations')"
test "$versions" = "19"
echo 'PHASE15_REAL_POSTGRES16_PACKAGED_MIGRATION_001_019_REPEAT_CONCURRENT_PASS'
