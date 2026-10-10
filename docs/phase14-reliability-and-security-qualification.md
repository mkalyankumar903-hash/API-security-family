# Phase 14 — Reliability, security and qualification record (isolated engineering only)

> **Authority warning:** This is a source-oriented engineering record, not proof that the whole original Phase 14 Master Prompt is satisfied. Baseline: Phase13 commit `b66243daf2f227489743f14794eed3f6e8afac27`, Draft PR #14 and successful Full #38047579278. Phase14 is stacked in Draft PR #15. Exact-final-HEAD Full validation, any remaining gaps and a separate independent security acceptance must be confirmed in GitHub, not assumed from this document.

## 1. Scope, non-negotiable trust boundary

- API Family may implement isolated synthetic offline API assessments, tenant-scoped PostgreSQL projections, deterministic reports, local private workers and CI reliability evidence. **Only** Main Platform Host can grant real identity, membership, commercial entitlement, asset ownership, execution permits and canonical VERIFIED_FIXED.
- `UNKNOWN ≠ SAFE`; `NO EVIDENCE ≠ SAFE`; `FIX_CLAIMED ≠ VERIFIED_FIXED`; `CI PASS ≠ VERIFIED_FIXED`; `PAYMENT SUCCESS ≠ EXECUTION AUTHORITY`; `ENTITLEMENT ALLOW ≠ SCANNING PERMIT`; `SYNTHETIC AUTHORITY ≠ PRODUCTION HOST AUTHORITY`.
- Production boot remains fail-closed. No new production Host token issuers, real network target scanning, external QA receipts, real webhook delivery, payments, real subscriptions or release.
- Migrations 001–019 **must not** change. No Phase14 migration is included unless an independently identified DB schema defect requires a forward-only additive 020.

## 2. State-machine / authority / test register

The rows here point to actual accepted historical implementation and new Phase14 changes. “Test” identifies intended executable coverage; actual results are authoritative only once the exact commit's Actions log demonstrates execution.

| State machine | Authoritative state and valid transitions | Actor, authorization and transaction boundary | Idempotency, retry and terminal recovery | Test / diagnostic |
|---|---|---|---|---|
| Target lifecycle | `api_targets` ACTIVE/SUSPENDED/REVOKED/ARCHIVED and revision history | Synthetic HTTP tenant identity; `withTenant` with FOR UPDATE | Idempotency key binds input; terminal evidence persists | Phase01/Phase10 PG and Chromium; HTTP_REJECTED |
| Offline specification | `api_specifications`, inventories and operations | Tenant RLS, imported document must remain offline; size/depth/operation guards | Content fingerprint and immutable readback; invalid input denied | `engine.test.ts`, `phase2-isolated.test.ts`, Phase14 performance; RESOURCE_REJECTED |
| Assessment admission | `api_assessments` QUEUED→PROCESSING→COMPLETED or FAILED/CANCELLED | Tenant-scoped Fastify transaction and capacity-limited DB queue function | Tenant idempotency; no fabricated success; completion based on persisted report | Phase10 capacity/interleavings; Phase14 HTTP; HTTP_REJECTED |
| Queue entry/claim | `api_queue.api_assessment_queue` eligible→fenced lease→released/deleted | Restricted `api_family_queue` SQL principal; serialized claim gate, SKIP LOCKED | Claim token + generation; stale owner cannot commit; fair scheduling by tenant | Phase10/11 PG separate-process races; DB_CONTENTION |
| Worker attempt | `api_worker_attempts` ACTIVE→FAILED/LOST/COMPLETED | Private worker, DB transactional claim/heartbeat/finish | Attempt IDs unique, stale generation rejected; restart via authoritative DB | `phase10-acceptance-races.pg.test.ts`; WORKER_RETRY |
| Infrastructure retry | Queue retry_count/next_eligible_at and `api_worker_quarantine` | `scheduleConservativeRetry` under stop→permit/target→queue locks | Only transient pre-execution SQL errors; ≤3 retries with 2/4/8-second backoff, quarantine on exhaustion; terminal FAILED, never success | `phase10-retry.pg.test.ts`, `safety-retry.ts`; WORKER_RETRY |
| Permit / revocation | `api_pt_permits`, scopes, emergency stop, job deadline | Existing synthetic-only signed permit owner; transactional stop/revoke validation | No renewal or retry after revocation; no accidental resurrection | Phase06/10/11 PG and crash; AUTH |
| Parent/child workflow | `api_pt9_plans`, stages, parent report | Tenant-scoped worker, signed synthetic authority | Cannot report parent COMPLETED if child evidence absent; retry preserves immutable evidence | Phase09/11 PG and Chromium; CONFLICT |
| Report finalization | `api_reports`, Phase11/12 immutable snapshots | Tenant-scoped transaction and canonical local report authority (not VERIFIED_FIXED) | No duplicate immutable report; failed/cancelled stays non-successful | Phase11/12 PG + actual Poppler PDF; CONFLICT |
| Usage reservation | `api_v13_reservations`, expiry and settled states | CI synthetic HMAC only, tenant-feature advisory transaction | Unique feature/version/source idempotency; terminal expire/settle not double-counted | Phase13 PG, crash child SIGKILL; CONFLICT |
| Usage ledger | `api_v13_usage_ledger`, corrections | Tenant RLS, immutable evidence-backed synthetic meter | Corrections append-only; replay blocked and actual source rechecked | Phase13 PG/upgrade + DR fingerprints; CONFLICT |
| QA delivery | `api_v13_qa_delivery*`, `api_v13_qa_sink_receipts` | CI-only `api_family_qa_ci` SQL login, FORCE RLS, app and queue role denied | Fenced ACK/retry/dead-letter; real outbox forever DISABLED; sink dedupe | Phase13 QA isolation / 7 SIGKILL child processes; AUTH |
| SDK request | HTTP GET response, not canonical state | Caller-supplied bearer only; no tenant override; same approved origin | Opt-in 0..2 GET retries only for transport/429/502/503/504; 1 MiB cap; abort and timeout fail closed | Phase13/14 contract tests; TRANSPORT_OR_TIMEOUT |
| React readback | Local selected target and tenant token; authoritative HTTP+PG read | React SDK from selected synthetic identity | Aborts stale requests, clears old projections on context switch, displays Host not configured | Phase13 and Phase14 real Chromium; HTTP_REJECTED |

## 3. Current Phase14 source changes

- `packages/service/src/diagnostics-v14.ts`: bounded, enumerated operation/error taxonomy; request IDs accept only short hex/hyphen; duration/attempt/queue waiting are finite bounded numbers; never serializes original errors, response bodies, secrets, target URLs or tenant IDs. Output only if `API_FAMILY_DIAGNOSTICS=true` and `NODE_ENV!==production`.
- `packages/service/src/app.ts`: 128 simultaneous Fastify admission ceiling (429, release on response/abort), request latency measurement via monotonic clock, `Cache-Control: no-store` for success and errors, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`; existing explicit localhost-only CORS retained. This admission ceiling grants **no** execution authorization.
- `packages/sdk/src/v13.ts`: token-provider errors are redacted; disallows unsafe base path/origin, oversized responses and malformed schemaVersion; opt-in bounded read-only retries, abort handling; redirects already refused. SDK remains unpublished and never creates real Host tokens.
- `tests/phase14-contract.test.ts`, `tests/phase14-http.test.ts`: actual HTTP security, hostile payloads, global capacity/recovery and SDK negative tests in `npm test`.
- `tests/phase14.pg.test.ts`: real PG16 simultaneous migrators, transaction rollback, tenant context reset, timeout, pool capacity, actual deadlock and measured tenant-filtered SQL.
- `tests/phase14-performance.test.ts`: offline 120-operation parse+assess fixed workload with 5 warmups, 30 iterations, median/p95, error count, heap delta; 8 simultaneous isolated imports, 4 admitted and 4 capacity rejections. No external customer load.
- `scripts/phase14-disaster-recovery.sh`: creates a *separate* synthetic restore DB from an isolated 019-schema database, compares six table fingerprints, verifies FORCE RLS and application denial of QA receipts and rejects an invalid custom-format archive. It is **not** an operational backup system.
- `tests/browser/phase14.spec.ts`: actual Chromium synthetic Host-blocked UI read failure and recovery, never invents scan authorization.
- `.github/workflows/phase14.yml`: stacked PR trigger targets Phase13, independent concurrency namespace, read-only GitHub token, exact SHA checkout, Node22 and PostgreSQL16; follows historical Phase13 Full tests and adds Phase14 qualification. Upstream third-party checkout/setup-node immutable commit SHAs verified via GitHub.

## 4. Performance and admission methodology

| Engineering workload | Warm-up | Iterations | Concurrency | Metric | Acceptance interpretation |
|---|---:|---:|---:|---|---|
| 120 operation offline JSON spec parse + assessment | 5 | 30 | 1 | median/p95 wall clock, memory delta, errors | Baseline measurement only, **no** production latency SLO |
| Real tenant-context PostgreSQL filtered SELECT + commit | 5 | 30 | 1 with alternating 2 tenants | median/p95 transaction latency, errors | Isolated runner engineering sample; no SLO |
| Isolated worker import saturation | 0 | 8 admissions | 8 attempted; maximum 4 | 4 accepted/4 rejected expected | Capacity invariant, not target throughput |
| HTTP Fastify admission | 0 | 129 simultaneous requests | 128 maximum allowed | rejected request 429; slots fully released | Explicit overload behavior |
| Synthetic PostgreSQL logical backup/restore | 0 | 1 | 1 | elapsed ms; six fingerprint comparisons | Laboratory drill only; not RTO or RPO |

These workloads are run with disposable/loopback-only fixtures on GitHub-hosted runners. No valid millisecond CI regression **budget** may be invented from a first run. Record measured samples from Full logs, repeat on stable environment, then set defensible future CI thresholds with variability allowance; report both error rate and capacity rejection. Unverified dimensions (PDF p95, long-term queue fairness under saturation, process memory across full worker life, browser responsiveness) remain gaps until measured.

## 5. Fault classifications, safe recovery and operator diagnostic decision tree

| Condition | Safe decision | Authority and evidence |
|---|---|---|
| Transport/DB unavailable before durable work | Structured transient error; retry only if proven idempotent | Source-backed state read after restoration |
| Commit may have succeeded but ACK lost | Never replay arbitrary mutation; read exact idempotency/source record first | PostgreSQL immutable ledger and source fingerprint |
| Worker expires or is SIGKILLed | Lease reclaimed by fenced generation, old attempt LOST; no stale commit | Queue/worker attempts database |
| Permanent malformed spec or invalid permit | Non-retryable failure; do not treat as safe finding | Validation and signed permit authority |
| Tenant-scoped resource ceiling reached | Before-admission 429 with clear diagnostic; preserve prior work | API response + independent queue readback |
| QA receipt crash before ACK | CI-only dedupe/recovery; real outbox remains DISABLED | RLS-protected QA sink ledger |
| Cancel/revoke in-flight | No new unauthorized work; preserve historical immutable evidence | Scope/permit/deadline/stop transition |
| Missing report/Host | UNKNOWN, never successful or verified-fixed | Host not configured and persisted report absence |
| Backup restore failure | Fail closed, preserve original data and logical backup; no destructive rollback | Independent disposable restoration |

Production startup must fail closed rather than treat `/health/live` process liveness as Host availability or customer authorization. SQL admin credentials must never be a fallback for application, worker or QA roles. For a production emergency stop, the authorized Host must revoke signed permits and stop admission; local synthetic emergency-stop tests are not external authorization.

## 6. Disaster-recovery runbook (lab only)

1. On a GitHub-hosted ephemeral PostgreSQL16 service, bootstrap isolated application, worker, migration-admin and CI-only QA principals. Apply migrations 001–019 verbatim.
2. Populate controlled synthetic tenant records via historical PG tests, preserving accepted immutable reports, usage and outbox records.
3. Run `bash scripts/phase14-disaster-recovery.sh api_family_phase13_pg_full` **in the same ephemeral job**, where `NODE_ENV=test`, synthetic flag and disposable local admin password are present.
4. Review `PHASE14_SYNTHETIC_BACKUP_RESTORE_PASS`, elapsed time, all six fingerprints, migration count, FORCE RLS and QA privilege denial. On any mismatch fail CI; do not “repair” by deleting ledger.
5. Deliberately malformed archive must fail. Preserve the original database. The script's temporary backup is destroyed at job completion, and none of this is a production backup retention policy.

Restored queue leases may require bounded expiry/reclaim under the existing fencing protocol. Credential rotation, cross-region replication, PITR, real production RPO/RTO and customer data backups are **not** qualified here. Historical migrations are forward-only; destructive schema downgrade should not be recommended. Production recovery should use authorized, version-controlled forward repairs after independent review.

## 7. Acceptance matrix — original scope vs current implementation

| Category | Current disposition (not a final CI PASS claim) |
|---|---|
| Lease fencing, limited retries, poison quarantine, fair scheduling | Historical Phase10–13 implemented; Phase14 source audit and full regressions pending |
| DB timeout, pool, contention, migration and transaction safety | Phase14 real SQL test suite committed; Full execution pending |
| HTTP admission and overload | Implemented, contract tests committed; Full execution pending |
| Offline parser bounds, reference dereference denial | Historical implemented; Phase14 load test committed |
| Redacted structured observability | Partial: HTTP allowlist, redaction tests; complete queue/lease/meter metrics not implemented |
| Whole-system measured performance | Partial: parsing and PG read; other categories still unmeasured |
| Multi-tenant load, stress and noisy neighbor | Partial: isolated import and HTTP global admission; comprehensive fairness and starvation qualification missing |
| Fault-injection/chaos | Historic real SIGKILL; broader deterministic DB service restart, PDF partial failure and all listed 16 scenarios not newly covered |
| Synthetic backup/restore | Script implemented, Full PG restore test pending |
| Fastify/API hardening | Partial: body, spoofing, response headers and request capacity tests; complete SSRF/error and content-type matrix pending |
| Reports/PDF/Unicode | Accepted Phase12/13 Poppler tests preserved; extended Phase14 PDF chaos/performance not complete |
| Metering and QA privilege isolation | Historical 3 non-billable meters, migration 019 and 7 actual SIGKILL tests preserved |
| SDK reliability | Phase14 enhanced and negative tested; cannot claim full runtime compatibility/HTTP classification matrix yet |
| React failure UX/accessibility | Historical Phase13 plus Phase14 failure-recovery Chromium; full required accessibility matrix not complete |
| Startup, supply chain, CI | Partial: production fail-closed preserved, workflow actions SHA pinned; dependencies/advisory triage incomplete |
| Comprehensive exact final SHA | PENDING until `[phase14-full]` actual Full job executes |

**Independent engineering scope must never be labeled HOST_BLOCKED simply because it is incomplete.** Additional independently executable gaps require targeted rework, not claims of engineering completion. True HOST_BLOCKED: Main Platform production JWKS/membership, ownership, subscription and billing entitlement authority, real execution authorization, external delivery and canonical RetestVerificationAuthority.

## 8. Closeout requirements

Phase14 acceptance requires **branch SHA = PR SHA = exact successful Full CI SHA**, genuine executions of 001–019 upgrades, real PostgreSQL role isolation and separate-process crash recovery, Poppler PDF parser, Chromium React/Fastify/PG, SDK ESM package dry-run, lint, strict TypeScript, measured benchmarks and recovery drills. Any later source/documentation commit invalidates previous final-head qualification. Mandatory tests may never be disabled to make green. PR #15 must remain OPEN / DRAFT / UNMERGED, and original PR #14 unchanged. No merge, deploy, SDK publish, external target execution or Phase15.
