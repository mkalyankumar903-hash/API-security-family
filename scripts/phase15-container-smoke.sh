#!/usr/bin/env bash
set -euo pipefail
test "${GITHUB_ACTIONS:-}" = "true"
docker build --pull --target api-service -f Dockerfile.phase15 -t phase15-api-service:ci .
docker build --pull --target private-worker -f Dockerfile.phase15 -t phase15-private-worker:ci .
for image in phase15-api-service:ci phase15-private-worker:ci; do
  test "$(docker image inspect --format '{{.Config.User}}' "$image")" = "node"
  test "$(docker image inspect --format '{{index .Config.Env 0}}' "$image" | cut -d= -f1)" != "PHASE15_SIMULATOR_ENABLED"
  set +e
  output="$(docker run --rm --network none --read-only --tmpfs /tmp:rw,nosuid,nodev,size=64m "$image" 2>&1)"
  status=$?
  set -e
  test "$status" -ne 0
  grep -q 'HOST_AUTHORITY_NOT_CONFIGURED_PRODUCTION_FAIL_CLOSED' <<< "$output"
  ! grep -Eq 'local_admin_only|PRIVATE KEY|PT_TEST_SIGNING_KEY=' <<< "$output"
  echo "PHASE15_UNPUSHED_NONROOT_READONLY_CONTAINER_FAIL_CLOSED_PASS: $image"
done
