# Phase15 private release candidate — install, upgrade, safety, incident and recovery runbook

**Scope:** isolated, disposable GitHub-hosted acceptance only. Production live service and Host integration remain deliberately **disabled**. Do not use on customer data or endpoints. These commands are documentation for the GitHub Actions environment, not a request to use the founder laptop.

## Candidate evidence and acquisition

Read exact source SHA and release `manifest.json` and `SHA256SUMS` from private [PR #16](https://github.com/mkalyankumar903-hash/API-security-family/pull/16) comprehensive `[phase15-full]` workflow artifact. Compare branch/PR/run HEAD, candidate version `0.15.0-rc.1`, each archive checksum and byte count. Never trust filenames as release authority. Verify `node scripts/phase15-verify.mjs` PASS and the two-build checksum comparison; hashes detect changes, they **are not a trusted signature**. No release to npm, OCI registry, or public download is approved.

## Clean isolated deployment procedure

1. Provision fresh PostgreSQL **16** with independent privileged migration login, least-privilege application login and worker/queue login; create only disposable CI synthetic principals.
2. Extract `api-service.tar.gz`, `api-worker.tar.gz` into distinct empty directories. Reject traversal, symlinks, unexpected credential/env/cert files and any checksum mismatch.
3. On Node **22**, run `npm ci --omit=dev --ignore-scripts --no-audit --no-fund` from each extracted artifact's root. Never copy checkout `node_modules` or install `tsx` in runtime.
4. Configure database URLs from CI masked secrets, never put credentials in archives or Git commits. Set `NODE_ENV=test`, GitHub-only synthetic fixtures, isolated permit/scope signing roots; do not reuse any CI test root in production.
5. Apply unchanged bundled migrations **001–019** using `node packages/database/src/migrate.js` with the privileged `MIGRATION_DATABASE_URL`. Check schema migration count=19. Exercise repeat and concurrent invocations. Require schema owner grants, FORCE RLS, private worker schema separation, app/QA denial and no search_path bypass.
6. Start `node packages/service/src/server.js` and `node packages/worker/src/main.js` only inside a disposable isolated CI runner. Verify `/health/live` indicates **process liveness only**, not Host readiness. CI E2E must prove offline OpenAPI SPEC_ONLY import→worker→report with RLS and SDK readback.
7. Test SIGTERM process stop/restart, persisted report SHA-256, idempotent queue results, wrong-tenant deny, and prod startup **HOST_AUTHORITY_NOT_CONFIGURED_PRODUCTION_FAIL_CLOSED**. No external networking or real customer target.

## Upgrade and rollback policy

- Treat schema migrations as strictly **forward-only**. Do not delete, edit, reorder, replace, or rebaseline 001–019. Migration 020 is only for justified new schema requirements with forward/rollback semantics independently reviewed.
- Before an approved future upgrade, create an encrypted, access-controlled PostgreSQL backup and an immutable release artifact manifest. In isolated qualification, rehearse populated historical upgrade and backup/restore on a new DB; confirm RLS, permissions and report hashes survive.
- On failed migration or incompatible schemas, stop worker claims and deny service readiness. Do not continue scanning with partial schema or overwrite populated production DB to pass tests.
- On binary failure when DB is already migrated, use compatible previous binaries only after schema compatibility review. Do not perform destructive SQL rollback; use verified backup restoration in a separate controlled instance if authorized.
- On queue crashes preserve durable lease fences and queued jobs. Restart only with still-valid real Host permits once Level C is separately approved; in Phase15 production Host permits are **never available**.
- On checksum mismatch/quota discrepancy/replay/expired/revoked Host event, hard-deny, quarantine relevant events and log non-sensitive error codes; no success fallback.

## Operations, least privilege and incident handling

- Separate DB roles: migrations have owner privileges; API/worker cannot impersonate them, QA cannot mutate privileged queue/commercial tables. FORCE RLS and tenancy check must run on every database connection.
- Keep workers on denied-egress network and filtered filesystem, bounded execution time/CPU/memory and revocable queue leases. OCI CI candidates use `USER node`, read-only filesystem and `--network none` at production-denial smoke.
- Host 401/403 means reject authentication; 408/5xx means unavailable; 409 means stale/conflict; 429 means rate-limited. No local CI root or synthetic JWT fallback.
- On incident: stop processing, revoke real Host permits via the Host owner after future integration, preserve forensic/audit evidence with tenant access controls, rotate affected credentials, restore a verified backup in staging and requalify before restart.
- Lab timings are not an operational production availability SLO, RPO or RTO. Host must separately define and rehearse on-call handover, deployment, vault, network, monitoring, recovery windows and incident ownership.
- Phase14 LOW revocation diagnostic misleading-state risk stays open and is included in production review prerequisites.

## Approval / handover gates

**Level B** is accepted only after all exact-HEAD independent GitHub Full steps succeed and independent security reviewer signs off separately. **Level C remains HOST_BLOCKED** until Main Platform supplies production identity/JWKS, membership/RBAC, tenant/client/asset ownership, scope permits, paid entitlement, canonical finding/retest, events, target network authorization and hosted operational approval.
