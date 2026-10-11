# Phase 15 — pre-production Host integration handover (DRAFT)

## Responsibility boundary

| Main Platform Host authority | API Security Family owned | Joint contract |
|---|---|---|
| Identity JWT/JWKS, membership and RBAC | API Fastify, workers, tenant RLS | Identity assertions and trust root |
| Asset ownership and live scope authorization | Offline assessment, specification import and PT engines | Exact tenant/org/client + scope hash + permit binding |
| Billing/subscription snapshots | Local nonbillable usage and isolated decisions | Entitlement schema, revision, expiry |
| Canonical findings and remediation RetestVerificationAuthority | Immutable evidence, reports and read-only views | Projection mapping, event delivery, retest handoff |
| Production event destinations and hosting approval | Isolated queue/retries and diagnostic records | Versioned envelopes, HMAC replay/ordering, incident response |

No joint contract is approved or frozen by this file.

## Install and operational model

Candidate `0.15.0-rc.1` targets Node 22 and PostgreSQL16; package manager lockfile is frozen. Use `npm ci` for build only, `node scripts/phase15-build.mjs` to create private archives under `build/phase15-release/`. `manifest.json` and `SHA256SUMS` bind output to a Git SHA. No registry upload.

Compiled runtime archives `api-service.tar.gz` and `api-worker.tar.gz` are separate. After safe extraction and `npm ci --omit=dev --ignore-scripts`, start with `node packages/service/src/server.js` or `node packages/worker/src/main.js` in a **disposable isolated test environment only**. `node packages/database/src/migrate.js` uses the 19 original SQL migrations and requires separate `DATABASE_URL`, `WORKER_DATABASE_URL` and privileged `MIGRATION_DATABASE_URL`. These must not be embedded in artifacts.

Production is intentionally **disabled**, even with correctly installed packages: `HOST_AUTHORITY_NOT_CONFIGURED_PRODUCTION_FAIL_CLOSED`. No fabricated Host JWT, permit issuer, canonical VERIFIED_FIXED writer or real customer endpoint is supported.

## Host adapter minimum negotiation (not an endpoint implementation)

| Joint contract | Issuer / consumer | Version / expiry / replay / revoked | Production state |
|---|---|---|---|
| Identity, membership, RBAC | Host → API service and SDK integration | Host-signed trust root + audience + expiry and explicit revocation / TBD | HOST_BLOCKED |
| Target/scope and ownership | Host → API worker | Tenant/client/target revision/scope hash + permits / TBD | HOST_BLOCKED |
| Permit request/decision/revocation | Host → private worker | Permit request ordinal bound, expiry, revocation, exact issuer / TBD | HOST_BLOCKED |
| Entitlement projection | Host → API | Revision, expiry, replay, durable reconcile / TBD | HOST_BLOCKED |
| Canonical findings/events/retest | API evidence → Host canonical owner | Versioned immutable references, replay, idempotency, no plugin VERIFY / TBD | HOST_BLOCKED |
| Report and evidence reference | API → Host | Opaque tenant-bound metadata, no URLs as authority / TBD | HOST_BLOCKED |
| Mount, readiness and capability discovery | Host UI → API UI | Session change, async cancellation, fail closed / TBD | HOST_BLOCKED |

CI-only signed envelope tests use short-lived ephemeral random keys and explicit `NODE_ENV=test`, `GITHUB_ACTIONS=true`, `PHASE15_SIMULATOR_ENABLED=true`. Do not use CI proof as production authority.

## Recovery / security operations

- Migrations are forward-only, privileged migration role separate from tenant-facing/queue roles, FORCE RLS mandatory; never reset a populated production DB to pass tests.
- A valid `/health/live` proves process liveness only, not Host authorization or production readiness.
- On worker crash: preserve durable queue and lease fences, replay only idempotently with renewed valid Host permits; no unsafe fallback.
- On Host timeout/401/403/409/429/5xx: deny access, report safe non-sensitive codes and allow bounded recovery only after validated new authority.
- On incident: deny execution, halt queue claims, revoke actual permits through Host, preserve immutable reports and audit trails, restore approved backups and verify tenant isolation.
- No measured lab startup/restart value should be called a production SLO or RTO/RPO.
- Clean archives must contain no .env, credentials, signing keys, caches or customer fixtures.

## Remaining owners / approvals

Main Platform owner must provide approved real schemas and signoff for every joint contract, secure JWKS/issuer, tenancy, billing and canonical retest. API Family owner must complete independent Level B release/upgrade/package/container/Chromium/E2E qualification. Security reviewer must independently inspect exact source/artefacts/CI after candidate freeze. Current status: **NOT YET QUALIFIED**.
