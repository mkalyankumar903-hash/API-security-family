# Phase 08 — Independent Review Acceptance Checklist (evidence pending)

## Immutable scope
- Repository: `mkalyankumar903-hash/API-security-family`
- Stacked base: `fab1351fc1ab1655eecf376d41959b257f99f145`, accepted Phase07.
- Branch: `work/phase08-complete-api-pt-product`; Draft PR #9.
- Scope is **isolated synthetic API PT**, not real customer-target penetration testing.
- No external customer HTTP requests, no synthetic permit issuance in customer UI, no production Host JWT/JWKS/credential-vault binding and no canonical `VERIFIED_FIXED`.

## Requirement-to-evidence map

| Requirement | Source / qualification |
|---|---|
| Baseline target and offline imported OpenAPI specification | Accepted Phase00–05 contracts and `tests/phase08.pg.test.ts` |
| Preview/scope readiness and operator exclusions | `packages/service/src/pt-product.ts`, `/v8/pt/specifications/:id/plan-preview`; `SKIPPED` excluded, `BLOCKED` unavailable |
| Signed permit separate test authority | Accepted `packages/service/src/pt.ts`, `tests/phase06-security-qualification.pg.test.ts` and denied customer issuance |
| Eight deterministic rule revisions and evidence constraints | `packages/pt/src/detection.ts`; `tests/phase07-detection.test.ts` |
| Multi-rule worker and quota/governor | `packages/worker/src/pt-detection.ts`; Phase06 and Phase07 real Postgres tests |
| Persisted progress | `GET /v8/pt/jobs/:id/progress`; `tests/phase08.pg.test.ts` |
| Cancel, revoke and worker partial-failure terminal diagnostics | `packages/pt/src/terminal-coverage.ts`; `tests/phase08-coverage.test.ts`, `tests/phase08.pg.test.ts` |
| No fake successful reports | `GET /v7/pt/jobs/:id/report` remains 409 for incomplete; immutable `/v8/pt/jobs/:id/terminal-coverage` distinct |
| Tenant RLS, immutable append-only terminal snapshots | `packages/database/migrations/012_phase8_complete_pt_product.sql`; real Postgres test |
| Populated Phase07 -> Phase08 forward-only upgrade | `tests/phase08-upgrade.pg.test.ts`; preserves older reports, signed permits and Phase07 plan |
| Findings, evidence, remediation, filters, pagination | `packages/service/src/pt-product.ts`, `packages/ui/src/PtProductExplorer.tsx`; tests |
| History, compatible comparison and JSON export | Existing Phase05/07 read APIs retained, Phase08 history and React explorer |
| Real Chromium customer readback | `tests/browser/phase7.spec.ts`, `tests/browser/phase8.spec.ts` |
| Worker failure fencing and concurrency | Accepted Phase06/07 PostgreSQL race suites plus controlled Phase08 partial failure |
| Security posture | `UNKNOWN != SAFE`; `NO EVIDENCE != SAFE`; `CI PASS != VERIFIED_FIXED`; synthetic-only |

## Acceptance method

Only an actually executed and successful GitHub-hosted Phase08 comprehensive `full` job at the **same commit** as PR #9 qualifies final-head regression and E2E. It must include frozen dependency install, ESLint, strict TypeScript, unit/security suite, fresh PostgreSQL 001–012, populated 011→012, real PostgreSQL concurrency, production React build and Chromium browser suites. Targeted success does not qualify a changed head. An independent reviewer must still accept source/security findings.

## Explicit limits

- This phase does not perform real customer API scanning or prove an absence of vulnerabilities.
- Synthetic observed outcomes are not canonical customer findings.
- Saved report human-readable rendering and JSON read/export are in the accepted Phase07 reporter; this phase does not add PDF/white-label delivery.
- Offset paging is stable by timestamp plus UUID for assessments. Findings include deterministic rule and ID tie-breakers.
- Terminal coverage is distinct from successful reports, and fixture evidence cannot set `VERIFIED_FIXED`.
- In live worker interruption, operation revocation is enforced at the existing governor boundary; in-flight HTTP cancellation is not represented as preemption.
- No Phase09 onward features are delivered here.
