# Phase09 deterministic autonomous orchestration — implementation and qualification

## Scope

This phase implements isolated, repository-owned synthetic API PT orchestration only. No Host production identity, customer credential vault, trusted egress, live API scanning, canonical Host finding promotion or verified-fixed authority exists. No source-level AI attack planning is permitted.

## Source-grounded reuse matrix

| Authority | Existing source | Phase09 integration |
| --- | --- | --- |
| Private queue | `packages/database/src/index.ts:claimJob` | Existing `processOneJob` dispatch of `pt-orchestrator-v1` |
| Signed synthetic permits | `packages/pt/src/permit.ts` | Same issuer, signed claims, MAC, revocation and hardening |
| Governor | `packages/worker/src/pt.ts` | `governedPtDetectionInteraction`, `withGovernedPtDetectionPublication` |
| Detector | `packages/pt/src/detection.ts` | Exactly eight versioned rules and evidence classifications |
| Terminal coverage | `packages/pt/src/terminal-coverage.ts` | Failed/cancelled evaluation accounting, never a success report |
| Test fixture | `packages/pt/src/security-fixture.ts` | Trusted in-process fixture; no customer HTTP |
| Product API | `packages/service/src/pt.ts` | Existing scope, permit, cancellation and emergency stop contracts |
| Customer UX | `packages/ui/src/AssessmentApp.tsx` | Additive React console, no browser signing |

## Versioned policy and plan

Four trusted, versioned profiles: SYNTHETIC_PT_BASELINE, SYNTHETIC_PT_AUTHORIZATION_FOCUSED, SYNTHETIC_PT_DATA_EXPOSURE_FOCUSED and SYNTHETIC_PT_COMPLETE_SUPPORTED. Deterministic stage construction uses the Phase07 rule catalog. Supported stages are PREFLIGHT, AUTHENTICATION, AUTHORIZATION, RESPONSE, RECONCILIATION and FINALIZATION, omitting empty policy categories. The canonical fingerprint excludes timestamps and job identities, but binds tenant, target, specification, scope, permit, fixture and policy.

The profile may select only trusted rule IDs; no customer-supplied stage code, scripts, HTTP destinations or exploit payloads. Each planned evaluation must be explicitly within the immutable scope, operation allowlist and rate/budget limits. The internal plan is not an execution permit.

## State and recovery

Migration 013 adds immutable plan snapshots, stage rows, append-only decisions, immutable successful reports and immutable terminal summaries. Existing Phase07 detection evaluation identities remain the canonical governor ledger. No new permit ledger or public worker queue is introduced.

The private worker checks signed scope/permit and current claim before every stage transition. Each real fixture interaction invokes the Phase06 governor. Consumed receipts can be reconciled after a crash without re-execution. Reserved/uncertain interactions are never blindly replayed. Stage dependency status is persisted in PostgreSQL. A failed run publishes only terminal coverage and cannot publish a successful report. Final report and job completion are in the same authority-checked transaction.

The accepted Phase06 lease is 60 seconds and job deadlines are at most 30 seconds; Phase09 does not claim distributed worker failover or arbitrary parallel execution. Operation-boundary cancellation is supported; forcibly interrupting an already synchronous fixture call is not claimed.

## Customer API

Versioned `/v9/pt/` endpoints expose trusted policy profiles, scope preview, authorization readiness, idempotent run admission, persisted stage progress, decisions, reports, terminal summaries, bounded history, compatible comparisons, exports and cancellation. Access derives from the existing tenant identity, enforced again by FORCE RLS. The React console operates through these APIs and never holds the test-signing key.

## CI strategy

GitHub-hosted Ubuntu, PostgreSQL 16, Node22 and Chromium only. Fast CI performs frozen install, lint, typecheck and all unit/security regressions. Targeted PG and browser tests are invoked with `[phase09-pg]` and `[phase09-e2e]`. An authoritative `[phase09-full]` run must execute its actual full job at the exact final branch and Draft PR SHA.

Status remains **NOT VERIFIED / INCOMPLETE** until actual PostgreSQL, Chromium and final-head Full CI results are collected. Test counts and unverified concurrency scenarios must be recorded from successful run evidence, never inferred.

## Security invariants

UNKNOWN ≠ SAFE; NO EVIDENCE ≠ SAFE; FIX APPLIED ≠ VERIFIED_FIXED; CI PASS ≠ VERIFIED_FIXED; AUTONOMOUS PLAN ≠ AUTHORIZATION; UNCERTAIN ≠ SUCCESS; SYNTHETIC OBSERVATION ≠ CONFIRMED CUSTOMER FINDING. Only an eventual independent Host RetestVerificationAuthority may set VERIFIED_FIXED.

No Phase10 implementation is included.

## Exact-state qualification evidence (9 October 2026)

Preserved Phase08 accepted base: `8cfd9697af8bb93d4656484c20cb86b5f429bf92`. Phase09 existing Draft PR is #10; keep it DRAFT/UNMERGED. No Phase10 and no Host canonical verification.

- Fast CI [#37974887916](https://github.com/mkalyankumar903-hash/API-security-family/actions/runs/37974887916): SUCCESS at `63385c7635a02555c56a41c8038b35cdd32a8bdf`; actual lint, TypeScript and unit/security suites executed.
- Targeted PG16 [#37974448743](https://github.com/mkalyankumar903-hash/API-security-family/actions/runs/37974448743): SUCCESS at `689e8dc45c221a3d41529202b5e94e2317ded53c`; 25 independently coordinated race/fault subtests PASS, one parent suite PASS, populated 012→013 migration and worker/Governor integration PASS.
- Targeted real Chromium [#37973824172](https://github.com/mkalyankumar903-hash/API-security-family/actions/runs/37973824172): SUCCESS at `e9bd678032c2405f63b3f43eb85dfb2e56ed946b`; phase6–phase9 browser suites executed with actual PostgreSQL 16 and private worker.
- Final-head comprehensive GitHub-hosted Full CI MUST pass its **full job**, including full predecessor regressions, migration 001–013, all Phase09 planner tests, the 25 real PG fault/concurrency subtests, React build and Chromium E2E. Partial or skipped jobs do not qualify.

### Phase09 requirement-to-evidence matrix

| Requirement | Code / independently runnable gate |
| --- | --- |
| Deterministic versioned trusted plans; no arbitrary stage code | `packages/pt/src/orchestrator.ts` and `tests/phase09-planner.test.ts` via `npm test` |
| Signed authorization, stable scope/target/spec binding and no production egress | `packages/service/src/orchestrator.ts`, `packages/worker/src/pt.ts`; Phase09 PG and browser suites |
| Budget, rate, concurrency and stop/revocation race safety | `tests/phase09-races.pg.test.ts` — 25 separate subtests, `npm run test:pg` |
| Stage dependencies, exact evaluation ownership and lease takeover | `packages/worker/src/pt-orchestrator.ts`, `tests/phase09-planner.test.ts`, PG and Chromium recovery tests |
| Immutable plan/evidence; stable terminal truth; no forged successful publication | Migration 013, `orchestration-terminal.ts`, PG real fault-injection tests |
| Additive 012→013 upgrade with historical signed permit preservation | `tests/phase09-upgrade.pg.test.ts` |
| Tenant isolation, idempotent admission and customer-visible product surfaces | Fastify `/v9/pt` routes, React `PtOrchestrationConsole`, PostgreSQL + Chromium |
| Synthetic-only wording, report/export, history/comparison, FAILED/CANCELLED uncertainty | Fastify routes, `docs/phase09-openapi.yaml`, Chromium tests |

**Interpretation:** a successfully completed isolated synthetic PT run is never a confirmed customer vulnerability, Host authorization, production scanning permission or VERIFIED_FIXED. No evidence ≠ safe. A failed or cancelled run publishes diagnostic terminal evidence rather than a successful report.
