# Phase 10 — Requirement / Source / Test Evidence Matrix

**Status:** seven originally outstanding Phase10 PG races, eight genuine disposable-worker/database-fault checkpoints and broadened 013→014 populated synthetic history all pass targeted GitHub-hosted PostgreSQL. Final-head comprehensive Full CI and independent security acceptance remain separate mandatory gates.

**Accepted predecessor:** `34b8b93afe17d336d931ffb7bb7e27025388f28f` (Phase 09, 112 unit / 90 PostgreSQL / 17 Chromium previously accepted). **Phase 10 branch:** `work/phase10-advanced-workers-execution-safety` stacked onto accepted Phase09. **Isolation:** synthetic-only; no customer networks; no Host-issued permits; no VERIFIED_FIXED.

## Requirement-to-code-and-evidence matrix

| Phase10 required engineering domain | Authoritative source | Execution evidence / test path | Review status |
| --- | --- | --- | --- |
| 1. Private PostgreSQL queue | `database/migrations/014...`, `database/src/index.ts:claimJob` | `phase10.pg.test.ts`, historical `phase09-races.pg.test.ts` | IMPLEMENTED_AND_TARGETED_TESTED |
| 2. Concurrent worker claiming | `claimJob`, private claim gate / `SKIP LOCKED` | `phase10.pg.test.ts`, `phase10-lifecycle.pg.test.ts` multi-session claims | IMPLEMENTED_AND_TARGETED_TESTED |
| 3. Owned lease / generation | `api_assessment_queue.claim_generation`, `api_worker_attempts` | `phase10.pg.test.ts` expired-claim takeover | IMPLEMENTED_AND_TARGETED_TESTED |
| 4. Deadline-bounded renewal | `database/src/index.ts:renewWorkerClaim` | `phase10.pg.test.ts`, `phase10-authority.pg.test.ts` | IMPLEMENTED_AND_TARGETED_TESTED |
| 5. Stale ownership fencing | `worker/src/index.ts`, governed Phase06/07/09 publication boundaries | `phase10.pg.test.ts`, `phase10-lifecycle.pg.test.ts`, Chromium D, predecessor Phase09 races | IMPLEMENTED_AND_TARGETED_TESTED; exhaustive paths pending |
| 6. Conservative crash recovery | `worker/src/pt-orchestrator.ts`, attempt trigger 014 | `phase10-fault.pg.test.ts` real child SIGKILL and backend disconnect across 8 distinct checkpoints | TARGETED_PASS; Full CI pending |
| 7. Bounded infrastructure retries | `worker/src/safety-retry.ts` | `phase10-contract.test.ts`, `phase10-retry.pg.test.ts`, Chromium E | IMPLEMENTED_AND_TARGETED_TESTED |
| 8. Duplicate-delivery suppression | Claim generations; unique evaluation ledger, immutable report indexes | `phase09-races.pg.test.ts`, `phase10-fault.pg.test.ts` | IMPLEMENTED_AND_TARGETED_TESTED |
| 9. Permit/budget preservation | Accepted `worker/src/pt.ts`, Phase06 permit ledger | `phase10-fault.pg.test.ts`, `phase10-authority.pg.test.ts` | IMPLEMENTED_AND_TARGETED_TESTED |
| 10. Cancellation | Accepted Phase06/09 cancellation and worker token checks | `phase10-acceptance-races.pg.test.ts` #7, original cancellation and Phase09 Chromium | TARGETED_PASS |
| 11. Revocation / stop | Accepted test authority and governor; renewed lease validation | `phase10-authority.pg.test.ts`, Phase09 Chromium; Chromium F | IMPLEMENTED_AND_TARGETED_TESTED |
| 12. Execution deadlines | `renewWorkerClaim`, existing signed job/permit boundaries | `phase10-authority.pg.test.ts` | IMPLEMENTED_AND_TARGETED_TESTED |
| 13. Per-tenant queue admission | 014 `api_enqueue_assessment`, 64-queue cap | `phase10-capacity.pg.test.ts` | IMPLEMENTED_AND_TARGETED_TESTED |
| 14. Fair tenant scheduling | `api_worker_tenant_schedule`, last-successful-claim ordering | `phase10-lifecycle.pg.test.ts` 7:1 tenants / independent claims | IMPLEMENTED_AND_TARGETED_TESTED; no production fairness guarantee |
| 15. Capacity/backpressure | Worker pool max 5, app max 12, 2 active per tenant, 64 queued, max batch100 | `phase10-capacity.pg.test.ts`, `phase10-lifecycle.pg.test.ts` | IMPLEMENTED_AND_TARGETED_TESTED |
| 16. Poison classification | Worker offline engine check, terminal attempt trigger, immutable plan denial | `phase09-races.pg.test.ts`, Phase10 negative audit | IMPLEMENTED_AND_TARGETED_TESTED — real constraint-valid poison and competing workers in `phase10-interleavings.pg.test.ts` |
| 17. Quarantine/dead-letter | 014 terminal immutable quarantine, retry-exhausted record | `phase10-retry.pg.test.ts`, Chromium E | IMPLEMENTED_AND_TARGETED_TESTED |
| 18. Transactional finalization | Accepted immutable report publication, 014 terminal-attempt trigger | `phase10-fault.pg.test.ts` before-finalization/after-report SIGKILL with exactly one durable report | TARGETED_PASS; Full CI pending |
| 19. Failure timeline/observability | `api_worker_attempts`, `api_worker_events`, queue metadata | `phase10.pg.test.ts`, Chromium A–G | IMPLEMENTED_AND_TARGETED_TESTED |
| 20. Operational read-only API | `service/src/worker-safety.ts`, `docs/openapi/worker-safety-v1.yaml` | `phase10.pg.test.ts`, Chromium A/G | IMPLEMENTED_AND_TARGETED_TESTED |
| 21. Real React lifecycle UI | `ui/src/PtOrchestrationConsole.tsx` | Chromium Phase10 A–G; existing Phase09 journeys | IMPLEMENTED_AND_TARGETED_TESTED |
| 22. Safe operator actions | Test-only stop/revoke and customer cancellation inherited; no replay button | Phase06/09 authenticated actions and security negatives | IMPLEMENTED_WITH_RESTRICTION — no new privileged Host operator API |
| 23. Least privilege and FORCE RLS | 014 restricted claim-token visibility; tenant FK; forced RLS | `phase10.pg.test.ts`, `phase10-upgrade.pg.test.ts` | IMPLEMENTED; final-head verification pending |
| 24. Independent PostgreSQL races | Existing multi-session PG race suites, Phase10 atomic claims, fairness, poison, retry/cancel | `phase10-acceptance-races.pg.test.ts`: 7 newly qualified independent PG interleavings; other Phase10/09 suites preserved | ALL SEVEN REWORK RACES TARGETED_PASS |
| 25. Genuine worker process faults | Disposable Node child SIGKILL after claim/heartbeat/evaluation/stage/report | `phase10-fault.pg.test.ts`: eight process SIGKILL/backend disconnect barriers | 8 CHECKPOINTS TARGETED_PASS; not exhaustive |
| 26. Historical compatibility | 014 forward migration, unchanged predecessors, old-engine dispatcher | `phase10-upgrade.pg.test.ts`: 7 engine discriminators plus populated Phase06/07/08/09 permit, report, plan and terminal history survive real 013→014 | REPRESENTATIVE UPGRADE TARGETED_PASS |
| 27. Real browser journeys | Existing Phase00–09 journeys plus Phase10 A–G | `tests/browser/phase10.spec.ts`, `phase10-recovery.spec.ts` | IMPLEMENTED_AND_TARGETED_TESTED; final-head recheck pending |
| 28. Comprehensive CI | `.github/workflows/phase10.yml` | Actual `full` job required at exact final HEAD | NOT_VERIFIED until full job success |

Statuses above indicate implementation/evidence category, **not Phase10 independent acceptance**.

## Required 25 Phase10 concurrency scenarios (executable evidence classification)

Classifications: `P10_DIRECT` = distinct Phase10 source test; `PREDECESSOR_RACE` = accepted Phase06–09 race test with related invariant; `BOUNDARY_ONLY` = tested sequentially but real concurrency not proven; `NOT_VERIFIED` = cannot count as passing.

| # | Mandatory scenario | Test/source evidence | Classification |
| --- | --- | --- | --- |
| 1 | Two workers same job | `phase10.pg.test.ts` parallel claims | P10_DIRECT |
| 2 | Many workers contend | `phase10-lifecycle.pg.test.ts` four independent claims | P10_DIRECT |
| 3 | Duplicate tenant idempotency | `phase09.pg.test.ts`, `phase10-capacity.pg.test.ts` | PREDECESSOR_RACE |
| 4 | Competing takeover after expiry | `phase10.pg.test.ts` | P10_DIRECT |
| 5 | Stale heartbeat | `phase10.pg.test.ts` | P10_DIRECT |
| 6 | Stale completion | Phase09 races and guarded offline completion | PREDECESSOR_RACE |
| 7 | Stale cancellation | `phase10-acceptance-races.pg.test.ts` #7: stale release/customer cancel contend on locked row, generation/attempt/zero-report readback | P10_DIRECT |
| 8 | Stale queue deletion | Chromium D with old token and generation | P10_DIRECT |
| 9 | Old worker vs renewed lease | `phase10-acceptance-races.pg.test.ts` #9: stale/current renewals compete on independent PG sessions; fenced token/generation readback | P10_DIRECT |
| 10 | Lease renewal vs expiry | `phase10-acceptance-races.pg.test.ts` #10: locked lease expiry commits before renewal; report absent | P10_DIRECT |
| 11 | Renewal vs cancellation | `phase10-interleavings.pg.test.ts` concurrent app and worker sessions | P10_DIRECT |
| 12 | Renewal vs emergency stop | `phase10-acceptance-races.pg.test.ts` #12: real held stop row, trusted stop defeats renewal | P10_DIRECT |
| 13 | Renewal vs deadline | `phase10-acceptance-races.pg.test.ts` #13: job deadline changes behind real lock; renewal and retry denied | P10_DIRECT |
| 14 | Retry vs cancellation | `phase10-interleavings.pg.test.ts` independent app/worker sessions | P10_DIRECT |
| 15 | Retry vs permit revocation | `phase10-acceptance-races.pg.test.ts` #15: trusted revoke and retry queue on actual permit/stop locks; no new budget/receipt | P10_DIRECT |
| 16 | Retry exhaustion vs terminal | `phase10-acceptance-races.pg.test.ts` #16: actual terminal lock beats fourth retry, no quarantine or report | P10_DIRECT |
| 17 | Poison vs claim | `phase10-interleavings.pg.test.ts` three concurrent worker claims, terminal poison | P10_DIRECT |
| 18 | Tenant queue imbalance | `phase10-lifecycle.pg.test.ts` seven-to-one load | P10_DIRECT |
| 19 | Worker capacity saturation | `phase10-capacity.pg.test.ts` concurrent 429 | P10_DIRECT |
| 20 | Budget reservation competition | `phase06-races.pg.test.ts`, `phase09-races.pg.test.ts` | PREDECESSOR_RACE |
| 21 | Rate-limit competition | `phase06-races.pg.test.ts` | PREDECESSOR_RACE |
| 22 | Concurrent report publication | `phase09-races.pg.test.ts` | PREDECESSOR_RACE |
| 23 | Cancellation vs success commit | `phase09-races.pg.test.ts` | PREDECESSOR_RACE |
| 24 | Permit revocation vs fixture | `phase09-races.pg.test.ts` | PREDECESSOR_RACE |
| 25 | Emergency stop vs stage | `phase09-races.pg.test.ts` | PREDECESSOR_RACE |

**All seven originally unqualified Phase10 cases #7/#9/#10/#12/#13/#15/#16 now have distinct independently executed PG lock-interleaving tests and readback.** PREDECESSOR_RACE cases remain explicitly differentiated; they do not represent new Phase10-specific execution.

## Process crash/fault matrix

| Fault checkpoint | Actual evidence | State |
| --- | --- | --- |
| After queue claim | `tests/helpers/phase10-disposable-worker.ts` + `phase10.pg.test.ts` SIGKILL | TARGETED_PASS |
| After heartbeat | same disposable worker and real OS termination | TARGETED_PASS |
| After governed evaluation receipt | `phase10-fault.pg.test.ts` after-evaluation child SIGKILL and durable no-replay readback | TARGETED_PASS |
| After stage checkpoint | same helper and independent worker recovery | TARGETED_PASS |
| After report commit/before process acknowledgment | `phase10-fault.pg.test.ts`; 014 atomic terminal attempt trigger | TARGETED_PASS — PG #37995876469 |
| Before queue claim | signal-aborted `processOneJob`; no process crash | BOUNDARY_ONLY |
| SIGTERM idle worker | `phase10-lifecycle.pg.test.ts` real worker exit | TARGETED_PASS |
| Before reservation, after durable reservation and after trusted fixture before receipt | 3 independent real OS SIGKILL barriers in `phase10-fault.pg.test.ts`; RESERVED→UNCERTAIN budget spent, never replayed | TARGETED_PASS |
| Before finalization, after stage, after report commit | `phase10-fault.pg.test.ts` real SIGKILL and durable stage/report/attempt comparison; not every SQL statement | TARGETED_PASS for these barriers; unsampled internal failures remain |
| DB backend disconnect between trusted fixture and receipt | `phase10-fault.pg.test.ts` real `pg_terminate_backend` on in-flight worker transaction and subsequent SIGKILL | TARGETED_PASS only for receipt window; claim/settlement disconnect not fully qualified |
| Deadlock, statement timeout and permanent DB fault | Classifier negatives without comprehensive independent PG fault injection | PARTIALLY_QUALIFIED; not claimed exhaustive |
| Permit revocation/cancellation during recovery | `phase10-authority.pg.test.ts`, earlier Phase09 races | PARTIALLY_QUALIFIED |

No generic exactly-once side-effect claim is made. At-most-once synthetic fixture attempts are only claimed where ledger identity and receipt state are demonstrably preserved.

## Canonical limits and lifecycle

- Isolated app pool `12`, worker pool `5`; `WORKER_DATABASE_URL` required. No service account or secret is exposed via Fastify.
- Claims: bounded serialized capacity gate, `FOR UPDATE OF q SKIP LOCKED`, 2 concurrent worker leases per tenant, 64 queued/active records per tenant. Last-successful-tenant scheduling favors a smaller eligible tenant when capacity exists.
- Lease 45 s / renewal 10 s; DB clock and earlier of original approved Phase06 job deadline or signed permit expiration govern renewal. Expired worker cannot renew or publish.
- Max `drainQueue` batch 100; idle polling 300 ms; SIGTERM/SIGINT stop new work; no unsafe release after evaluation. Initial unstarted claim can be released only with matching token/generation.
- Transient DB codes only before fixture/stage/ledger activity; deterministic 2, 4, 8 s; after three scheduled retries the next eligible failure is quarantine. No replay of consumed/RESERVED/UNCERTAIN fixture interactions.
- Read-only customer API permits 1–25 bounded history records and exposes no claim tokens or MAC keys. Existing Phase06 governor remains the sole authority for budgets, operation permission, target/scope validity and rate.
- Worker event history is append-only, and per-request history is bounded; lifetime retention/pruning and cross-region HA are **not** independently certified.
- No customer-controlled privileged replay/queue mutation. No Host permits or real customer scanning.

## Migration and compatibility evidence

Migration 014 is forward-only and leaves 001–013 unchanged. A genuine PostgreSQL clone at schema 013 contains **all seven supported historical engines**, existing offline reports and inventories, plus populated historical **Phase06 permit/job/fixture report; Phase07 detection plan/report; Phase08 FAILED terminal coverage; and Phase09 orchestration plan/report**. The representative archives are explicit **synthetic-only migration fixtures**, not live Host authority or fully validated historical synthetic executions. `tests/phase10-upgrade.pg.test.ts` snapshots every populated table and verifies stable row counts/fingerprints after actual 013→014, including original queued-record safe defaults and immutable report protections. The separate accepted 012→013 test also remains intact.

The expanded historical report upgrade passed hosted targeted PostgreSQL [run #38014305552](https://github.com/mkalyankumar903-hash/API-security-family/actions/runs/38014305552) at `f51da136ac038e4f3e6a49edea094d105a495838`. This demonstrates representative preserved schema states, **not all logically possible old rows or real production readiness**.

## Browser / PDF / hosted boundaries

Actual Chromium Phase10 A uses React→Fastify→PostgreSQL→worker→governor→detector→orchestrator→safety metadata. Journeys B–G cover genuine post-checkpoint OS SIGKILL, cancellation, replacement fencing, bounded terminal retry, emergency stop and tenant isolation. Historical Phase00–09 browser suites remain in the full runner.

The API Family product currently uses synthetic development bearer mappings, not the future Host login/SSO. JSON export and immutable synthetic reports are supported; a PDF report generator / future Host RetestVerificationAuthority is **outside Phase10** and must not be fabricated. Independent production identity, PDF and repeat-assessment guarantees cannot be inferred solely from worker tests.

**Security release gate:** All incomplete independently executable items remain review blockers until demonstrated. A green Full CI proves exactly the tests executed, not the unimplemented fault-matrix scenarios. Do not merge or begin Phase11 absent independent security acceptance.

## Most recent targeted evidence (source before this documentation update)

- [Phase10 PostgreSQL race, authority and migration targeted run #37995876469](https://github.com/mkalyankumar903-hash/API-security-family/actions/runs/37995876469): actual `postgres-targeted` job SUCCESS at `f7a233bdd3c4241ed4cc4c56a1bd0c1e941c0a35`. Includes the after-report SIGKILL, real poison competing workers, retry/cancel and renewal/cancel claims plus predecessor Phase09 faults. This is not a comprehensive Full CI and does not justify all 25 independent Phase10 races.
- [Phase10 Chromium targeted run #37994221844](https://github.com/mkalyankumar903-hash/API-security-family/actions/runs/37994221844): actual `browser-targeted` SUCCESS at earlier head, including Phase10 A–G and Phase06–09 journeys. A source change since then requires comprehensive exact-final-head requalification.
- The accepted Phase09 security governor and migrations 001–013 are unchanged; this document does not certify any untested Host capability or production high availability.

## Independent reviewer rework checkpoint

- [#38014062101](https://github.com/mkalyankumar903-hash/API-security-family/actions/runs/38014062101): targeted PostgreSQL job SUCCESS, seven direct controlled PG races #7/#9/#10/#12/#13/#15/#16, 8 child-process/backend-fault checkpoints, engine-version migration coverage, all existing targeted PG regressions.
- [#38014305552](https://github.com/mkalyankumar903-hash/API-security-family/actions/runs/38014305552): targeted PostgreSQL job SUCCESS, including broadened historical Phase06–09 report/plan/terminal preservation.
- Historical successful Full CI [#38009127618](https://github.com/mkalyankumar903-hash/API-security-family/actions/runs/38009127618) applied to **pre-rework HEAD only**. One authoritative `[phase10-full]` at final SHA still required.
- **Residual**: no exhaustive real backend deadlock/statement-timeout/permanent-fault/claim-disconnect coverage, multi-region reliability claim, production Host permit authority, customer scanning or `VERIFIED_FIXED` promotion. Independent acceptance pending; Draft PR #11 must remain unmerged.
