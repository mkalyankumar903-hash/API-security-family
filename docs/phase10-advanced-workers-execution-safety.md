# Phase 10 — Advanced Workers & Execution Safety

> Engineering implementation checkpoint, **NOT independently accepted**. This document distinguishes source implementation from evidence. Never classify this layer as permission for real customer API traffic.

## Baseline and non-negotiable boundaries

- Accepted immutable Phase09 parent: `34b8b93afe17d336d931ffb7bb7e27025388f28f`; Draft PR #10 remains open and unmerged.
- Draft Phase10 PR #11 is stacked on Phase09. Only additive migration `014_phase10_worker_execution_safety.sql`; migrations 001–013 are not rewritten.
- Governed execution still runs only repository-owned synthetic fixtures through Phase06 signed test authority and Phase07 evaluation ledger, with Phase09 checkpoints. Existing permit, rate, budget, evidence and verdict authority is not replaced.
- The private worker database principal owns the queue. A customer app cannot SELECT or mutate the private queue. The app obtains a narrowly tenant-checked read-only diagnostic projection through `public.api_worker_safe_queue_status`.
- `QUEUE CLAIM ≠ SECURITY PERMIT`; `HEARTBEAT ≠ AUTHORITY EXTENSION`; `RETRY ≠ NEW BUDGET`; `LEASE EXPIRED ≠ SAFE TO REPLAY`; `RESERVED ≠ NOT EXECUTED`; `UNCERTAIN ≠ SUCCESS`; `CI PASS ≠ VERIFIED_FIXED`.

## Execution-safety gap audit of accepted Phase09

| Source/requirement | Baseline finding | Phase10 change | Verification at documentation checkpoint |
| --- | --- | --- | --- |
| `packages/database/src/index.ts` atomic queue claiming | IMPLEMENTED_BUT_INCOMPLETE — `FOR UPDATE SKIP LOCKED`, fixed 60s | Private serialized capacity gate, tenant fair order, claim generation, active attempts | Source changed, PG qualification pending |
| Lease renewal | NOT_IMPLEMENTED | `renewWorkerClaim`, DB clock, bounded 45s renewal, job and permit expiry caps | Source changed, PG qualification pending |
| Ownership/fencing | IMPLEMENTED_BUT_INCOMPLETE — token checks in governors | Monotonic claim generation and persisted attempts | Stale-token boundary remains in accepted governor; broader generation checks pending |
| Recovery uncertainty | IMPLEMENTED_BUT_INCOMPLETE — governed reservation becomes UNCERTAIN and is not replayed | Preserve accepted ledger; attempt takeover recorded | Real process fault matrix incomplete |
| Retry classification | NOT_IMPLEMENTED for infrastructure failures | Explicitly classified transient codes only and only before any recorded fixture/stage activity, three bounded retry delays | Classifier unit coverage; PG fault qualification pending |
| Poison/dead-letter | NOT_IMPLEMENTED | Immutable terminal quarantine schema and conservative retry exhaustion | Unsafe replay UI is prohibited |
| Tenant fairness/backpressure | IMPLEMENTED_BUT_INCOMPLETE | Private last-claimed tenant schedule and cap of two active claims per tenant | Multi-tenant empirical fairness not yet qualified |
| Audit/diagnostics | IMPLEMENTED_BUT_INCOMPLETE | FORCED RLS attempts, append-only worker events/quarantine, read-only Fastify status route | Cross-tenant test added |
| Customer UX | NOT_IMPLEMENTED | Existing orchestration console now shows actual attempts, queue state and recovery signal | Chromium Phase10 journey added |
| Genuine process fault | NOT_VERIFIED | Disposable child worker and SIGKILL claim/heartbeat tests | Other crash points pending |
| Populated 013→014 migration | NOT_VERIFIED | Additive, defaulted column migration | Seeded historical fingerprints not yet exhaustively asserted |
| Final comprehensive Full CI | NOT_VERIFIED | Selectable `[phase10-full]` GitHub-hosted job | Do not mark done without successful exact-head run |

## State model and checks

Claiming occurs in one transaction through a non-blocking PostgreSQL claim gate, tenant fair ordering and `FOR UPDATE OF q SKIP LOCKED`. A private lease generation increments on each takeover. Attempt records use unique tenant/job/generation keys and record previous attempt as LOST before another is ACTIVE. This is **processing ownership**, never execution authorization.

Renewals require current token, current generation, nonterminal PROCESSING assessment, future lease and active tenant stop state, live target/scope/permit where applicable, and database clock caps. A 10-second best-effort heartbeat refreshes a 45-second lease. The original governor still independently serializes authorization at every fixture and publication boundary. A process crash may leave an ACTIVE attempt until a later takeover resolves it.

Conservative infrastructure retry classifies a deliberately small set of PostgreSQL transient errors. It is denied as soon as a Phase06 or Phase07 ledger row, or a nonpending Phase09 stage, exists. Retry never resets signed authority, consumed/reserved counts, permit rate counters or plans. Controlled exponential eligibility delays remain stored in the private queue, with a terminal immutable quarantine entry after exhaustion. Unsupported failure codes, uncertain evaluations and authorization failures never become automatic replay requests.

No customer route can force queue mutation or reissue permits. Customer view `GET /v10/workers/assessments/:id/execution?limit=20` returns `pt-worker-safety-v1` with tenant-scoped status, queue condition, historical attempts, events and quarantine. `limit` must be an integer from 1 to 25. No full bearer token or HMAC material may be returned.

## Operational controls and limits

- App pool: 12 connections; private worker pool: 5. Worker command retains bounded `drainQueue(max=100)` and existing 300ms idle poll interval.
- Queue claims: two active per tenant in Phase10 worker scheduling; existing Phase06 customer/permit/target concurrency admission is unchanged.
- Worker lease: 45 seconds; best-effort renewal every 10 seconds, bounded by job and permit expiry where applicable.
- Retry count: at most 3 retry schedules, with deterministic 2, 4 and 8 second delays; no jitter added to immutable fingerprints.
- Diagnostics: latest 1–25 attempts and events. All event metadata are bounded reason codes, not raw HTTP evidence.
- Unsupported: production HA certification, real customer scanning, Host permit authority, API canonical vulnerabilities, VERIFIED_FIXED, unrestricted privileged operations.

## GitHub-hosted qualification commands

Workflow: `.github/workflows/phase10.yml`.

- PR title without Phase10 marker → Fast: `npm ci --no-audit --no-fund && npm run lint && npm run typecheck && npm test`.
- `[phase10-pg]` → PostgreSQL 16 service, separate principals, migration+targeted historical and Phase10 PG tests.
- `[phase10-e2e]` → real Chromium with PostgreSQL and trusted synthetic test permit authority.
- `[phase10-full]` → exact SHA verification, complete unit/PG/Chromium/build regression commands. Ensure actual `full` job runs.

**The existence of a workflow, green Fast CI, or prior-head success does not qualify the final Phase10 commit.** GitHub Actions job IDs, measured test totals, failed and skipped jobs must be read directly from actual logs and recorded in PR #11 only after verified.

## Unqualified or incomplete executable gates

Beyond initial tests, this phase still needs independent multi-session measurements and proof for every mandatory race in the master prompt; process exits after reservations, fixture execution, evidence persistence, stage checkpoint, publication; PostgreSQL-fingerprint-preserving populated upgrade; full multi-tenant queue fairness and latency measurements; all Phase10 Chromium journeys; escalation/revocation/cancellation races; and comprehensive exact-final-head Full CI. Those are **NOT VERIFIED**, not `HOST_BLOCKED`. Do not merge or mark ready.

## Security review disposition

`INCOMPLETE / BLOCKED` until all independently executable Phase10 requirements pass and Phase10 final HEAD equals PR HEAD equals successful Full CI SHA. Main, Web Family, Main Platform and production must remain untouched.
