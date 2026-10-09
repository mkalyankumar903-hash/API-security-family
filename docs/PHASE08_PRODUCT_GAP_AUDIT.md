# Phase 08 — Source-based capability and qualification ledger

Repository: `mkalyankumar903-hash/API-security-family`. Phase 08 is an **isolated synthetic API PT product**, not real customer API penetration testing.

## Accepted Phase 07 baseline
- Accepted commit: `fab1351fc1ab1655eecf376d41959b257f99f145`.
- Accepted Full CI: https://github.com/mkalyankumar903-hash/API-security-family/actions/runs/37957489986
- Eight executable deterministic rules, Phase 06 governor, signed test permits, PostgreSQL 001–011, worker and React detection console all preserved.
- Existing PRs #1–#8 remain stacked and unmerged.

## Phase 08 capability matrix — source audit

| Capability | Phase 07 initial finding | Phase 08 implemented delta | Current evidence status |
| --- | --- | --- | --- |
| Targets, versioned specifications and inventory | IMPLEMENTED_AND_WIRED | Reused without separate registry | BASELINE_QUALIFIED |
| Synthetic PT scope and explicit operations | IMPLEMENTED_AND_WIRED | Preview projection introduced | TESTING |
| Separate signed test authority | ISOLATED_RUNTIME_QUALIFIED | No browser signing endpoint added | BASELINE_QUALIFIED |
| Phase 06 governor and worker fencing | ISOLATED_RUNTIME_QUALIFIED | Existing authority preserved | BASELINE_QUALIFIED |
| Eight evidence-backed detection rules | ISOLATED_RUNTIME_QUALIFIED | Existing rules and fixture versions preserved | BASELINE_QUALIFIED |
| Successful immutable synthetic reports | ISOLATED_RUNTIME_QUALIFIED | v7 report retained unchanged | BASELINE_QUALIFIED |
| Failed/cancelled rule-level coverage | PARTIAL | Migration 012 terminal summary + v8 diagnostic API + React display | TESTING |
| Real worker fault after partial evaluation | NOT_PRESENT in customer report | In-process private worker test hook, no HTTP access | TESTING |
| Global findings search and filters | PARTIAL | v8 tenant-gated finding projections + detail | TESTING |
| Progress from persisted evaluations | PARTIAL | v8 progress projection | TESTING |
| History filters and stable pagination | PARTIAL | v8 history projection | TESTING |
| Comparison | PARTIAL | Phase 07 compatible completed-report comparison retained | PARTIAL |
| Remediation | IMPLEMENTED_AND_WIRED | Rule-specific guidance surfaced by v8 finding detail | TESTING |
| Print/report presentation | PARTIAL | Existing human-readable React view retained | PARTIAL |
| JSON export | IMPLEMENTED_AND_WIRED | v7 versioned export retained | BASELINE_QUALIFIED |
| Full Phase 08 Chromium journeys | NOT_PRESENT | Existing Phase 07 E2E enhanced for terminal coverage | TESTING |
| Populated Phase 07 → Phase 08 database upgrade | NOT_PRESENT | Forward-only migration 012 implemented | NOT VERIFIED |
| Full Phase 08 security/performance/load tests | NOT PRESENT | Targeted tests in progress | NOT VERIFIED |
| Real customer scanning and Host permit | HOST_BLOCKED | Remains strictly disabled | HOST_BLOCKED |
| Canonical finding/VERIFIED_FIXED authority | HOST_BLOCKED | No authority introduced | HOST_BLOCKED |

## Failure diagnostics versus completed reports

The `api_pt8_terminal_coverage` table is FORCE RLS, tenant-owned, append-only and fingerprinted. A diagnostic is inserted inside the transaction that marks a governed job FAILED or CANCELLED. It never creates a successful PT report.

`NOT_RUN` means planned but no recorded fixture evaluation. `BLOCKED` requires denial evidence in the terminal cause. `INCONCLUSIVE` covers incomplete rule evidence and uncertain reservations. Complete per-rule fixture evidence can still give a *rule observation* without granting a final completed assessment. Missing evidence must never be interpreted as safe.

Accepted Phase 07 report rows stay immutable. The terminal summary is a distinct resource; rollback of an unsuccessful worker transaction cannot manufacture a report. No `VERIFIED_FIXED` is granted.

## Critical prohibitions and future work
- Production Host JWT/JWKS, ownership, organization delegation, credential vault, real permits, egress and canonical findings contracts are not frozen. No permissible fallback exists.
- All live customer-target execution remains blocked.
- Phase 09 autonomous orchestration, Phase 10 worker upgrades, Phase 11 autonomous VAPT, Phase 12 advanced reports, Phase 13 plugin SDK and Phases 14–15 Host qualification remain out of scope.
- This ledger is **not independent acceptance**. It must be updated only with actual final-head Full CI evidence and independent review.

## Reproduction
Hosted GitHub Actions: `.github/workflows/phase08.yml`. Commit marker `[phase08-full]` requests the authoritative full job. Intermediate changes use fast/targeted jobs. Do not run founder laptop software or self-hosted workers.
