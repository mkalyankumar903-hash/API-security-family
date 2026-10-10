# Phase 13 — Security and requirement closeout audit (isolated, non-production)

**Scope:** accepted Phase12 commit `31b8c402524dcc5e6d0c7fecf3a7c5b1262d4e6b`; existing Phase13 Draft PR #14. This document is committed with the implementation and becomes qualified only when GitHub Actions runs on **this containing commit**. The PR's final engineering evidence comment and description carry the exact commit SHA and successful job/run identifiers; avoid treating earlier-sha CI as evidence for later changes.

**Evidence baseline (historical, not final for this document):** exact SHA `e3a89be7a2a15bb3827439f562bbf46ee277f6e1`, run [#38038050938](https://github.com/mkalyankumar903-hash/API-security-family/actions/runs/38038050938), full job `114172534752`: 135 unit checks, 154 PostgreSQL, 2 actual PDF parser, 40 Chromium, ESLint/strict TS/build and SDK dry-run package PASS. This SHA preceded the delivery-state/feature-catalog/UX enhancements. The standalone historical job was skipped by design; its tests ran in comprehensive Full. The latest authoritative final-sha evidence must be checked on GitHub, not inferred from this older snapshot.

## Requirements, source, independently executable evidence

| # | Requirement | Source and verification | Status |
|---|---|---|---|
| 1 | Typed Host adapters and trust separation | `packages/contracts/src/commercial-v13.ts`; contract negative tests. Production Host bindings absent. | IMPLEMENTED_AND_VERIFIED (types); live connection HOST_BLOCKED |
| 2 | Signed entitlement expiry, revocation, revision | `commercial-v13.ts`, `phase13.ts`; strict event and revision PG tests. | IMPLEMENTED_AND_VERIFIED (synthetic) |
| 3 | Tenant quota/capacity decisions | PostgreSQL advisory locks, tenant-RLS projection and hard denial on `/v13/decisions`. Three versioned non-billable observation meter paths; immutable report, successful offline, authorized synthetic governed PT only; per-feature quota and signed entitlements in `phase13.ts` and tests. | IMPLEMENTED_PENDING_FINAL_CI |
| 4 | Source-backed idempotent metering | Three persisted immutable successful source types, keyed feature/version, strict source fingerprint plus duplicate and cross-feature idempotency denial; governed PT signed authorization and successful terminal receipt requirement. | IMPLEMENTED_PENDING_FINAL_CI |
| 5 | Reserve/settle/expire/release/recovery | `phase13.ts`, PostgreSQL TTL/race/replay tests. Independent PostgreSQL16 child SIGKILL fault tests at transaction barriers in `phase13-crash.pg.test.ts`; authoritative restart. | IMPLEMENTED_PENDING_FINAL_CI |
| 6 | Immutable ledger and signed correction events | Migration 017; signed correction, replay, bounds, cross-tenant negatives. | IMPLEMENTED_AND_VERIFIED |
| 7 | Concurrent transaction-safe quota | `pg_advisory_xact_lock`, simultaneous reserve tests, revocation/admission race. | IMPLEMENTED_AND_VERIFIED |
| 8 | Signed event tamper/replay and key rotation | Strict raw-byte MAC, clock skew/expiry, inbox event dedupe, test keyring unknown/expired negatives. | IMPLEMENTED_AND_VERIFIED (CI only) |
| 9 | Independent reconciliation and watermarks | Separate signed CI accounting snapshots, immutable mismatch history and signed corrections. Real external accounting absent. | IMPLEMENTED_AND_VERIFIED (synthetic); live HOST_BLOCKED |
| 10 | Transactional inbox/outbox | Real outbox strictly DISABLED, separate test-only synthetic sink, fenced lease/ACK/retry/dead-letter with durable redacted receipts in migration 018 and `phase13-delivery-qa.ts`; never external delivery. | IMPLEMENTED_PENDING_FINAL_CI (synthetic only) |
| 11 | Fastify API and OpenAPI | `packages/service/src/phase13.ts`, `docs/phase13-openapi.yaml`; versioned GET endpoints and schema contract. | IMPLEMENTED_AND_VERIFIED (isolated read-only) |
| 12 | SDK and packaging | `packages/sdk/src/v13.ts`; caller-supplied bearer; private Node ESM declaration build, dry-run pack, transport/error/paging tests. | IMPLEMENTED_AND_VERIFIED |
| 13 | React customer workspace | `Phase13Workspace.tsx`, browser Phase13 real React–Fastify–Postgres UI. | IMPLEMENTED_AND_VERIFIED (synthetic) |
| 14 | Migration 017, FORCE RLS, privileges | 7 old tables retained; 4 additive 018 tenant-isolated FORCE RLS tables; least-privilege grants, immutable historical records. | IMPLEMENTED_PENDING_FINAL_CI |
| 15 | Populated 016→017 historical upgrade | `tests/phase13-upgrade.pg.test.ts`; preserved 016→017→018 and populated 017→018 immutable report, entitlement, reservation, usage/outbox retention. | IMPLEMENTED_PENDING_FINAL_CI |
| 16 | Phase00–12 security invariants | All historical PostgreSQL, Chromium and actual PDF parser regressions must execute on the new final SHA. | HISTORICAL_BASELINE_PASS; FINAL_HEAD_PENDING |
| 17 | Production Host authorization and fail-closed | `HOST_AUTHORITY_NOT_CONFIGURED` decisions always deny; Main Platform tenant, JWKS and billing not supplied. | HOST_BLOCKED (boundary implemented) |
| 18 | Responsive, keyboard and localization foundations | Semantic labels/captions, keyboard, focus, mobile viewport, 200% text, reduced motion, RTL/expanded QA locale, target-context switching in real Chromium tests. No customer translations or formal WCAG certification. | IMPLEMENTED_PENDING_FINAL_CI (engineering foundation) |
| 19 | No-store and tenant isolation | Fastify no-store GET hook, tenant-scoped RLS readbacks, forbidden cross-tenant HTTP. | IMPLEMENTED_AND_VERIFIED |
| 20 | Exact final HEAD GitHub Full qualification | `.github/workflows/phase13.yml`, PR #14 evidence comment. Must match containing SHA. | VERIFY_FINAL_SHA_IN_PR |

## Security review
- **No real Host:** no JWT/JWKS, membership, real subscriptions, merchant callbacks or payments. Development tokens and CI HMAC fixture keys are never customer authorization.
- **No new scanning authority:** every `/v13/decisions` response returns `allowed:false`. A commercial entitlement does not mint a Phase06 signed permit, authorize a network, alter a finding or set `VERIFIED_FIXED`. UNKNOWN ≠ SAFE; NO EVIDENCE ≠ SAFE; FIX_CLAIMED ≠ VERIFIED_FIXED.
- **Evidence accounting:** three separate non-billable source-derived meters (distinct successful immutable Phase11 parent report; offline child completion with persisted offline report; and synthetic governed PT completion with persisted signed-body permit/terminal evidence) share NO quota. No claim that legacy Phase00–12 assessment routes are commercially gated. Failed/cancelled/no-report operations have no billable usage.
- **Feature catalog:** all three independent non-billable synthetic observation meters are implemented with distinct units and version-one binding; the two new meters are strictly CI/test-only and require qualified historical source evidence. Neither commercial accounting nor the feature catalog creates an assessment or permit.
- **Revocation/expiry:** admission and settlement re-check current test entitlement while serializing within tenant-feature advisory transaction; revoked states cannot become successful new usage.
- **Inbox/outbox:** signed event inbox and usage outbox are durable, immutable, tenant-isolated. Explicit DB delivery-state constraints keep all transmissions disabled; no production URL, lease or delivery credentials are configured. The separately isolated test-only delivery projection demonstrates idempotent sink receipt, fenced lease, ack, bounded retry and dead-letter without any external network; those are NOT production delivery.
- **Reconciliation:** independently signed CI external observations can produce MATCHED/MISMATCH; absent Host snapshot remains PENDING_EXTERNAL_AUTHORITY. Neither compares against an actual invoice.
- **UX:** pseudo-locale modes are test fixtures, not translations. No WCAG certification or production usability sign-off.
- **Pending engineering qualification:** multi-feature source-driven accounting, real process SIGKILL ledger/ACK recovery, and isolated synthetic delivery lifecycle are implemented in this rework but must actually execute and PASS at exact final HEAD before being declared verified. Outbound integration additionally needs approved Host envelope, trust roots, delivery security/authorization and legal business arrangements.

## Additive Phase13 recovery implementation — qualification matrix

| Focus | Source | Live test / enforced boundary |
|---|---|---|
| Versioned three-feature catalog | `commercial-v13.ts`, `phase13.ts` | all observations synthetic/non-billable, never Host or scan permits |
| Separate feature entitlements, quota, correction/reconciliation | `phase13.ts`, `018_phase13_multi_meter_recovery.sql` | `phase13.pg.test.ts` report/offline/governed PT, version-one columns, UTC month and timezone, cross-feature collision, independent corrections and signed snapshots |
| Historical source provenance | immutable Phase11 parent, completed offline `api_reports`, synthetic governed `api_pt9_reports`, historical permit `signed_body` and `token_hash` | source fingerprint revalidated at settlement; unsigned stored body cryptographically reconstructed with isolated CI trust at signed validity, plus completed PT stages and signed-permit-bound consumed synthetic PT9 evaluation rows; no bearer storage |
| Real SIGKILL before/after reservations and ledger/outbox commits, expiration and ACK recovery | `phase13TestFaultBarrier`, `phase13-crash-child.ts` | `phase13-crash.pg.test.ts`; independent PostgreSQL16 test DB and child restart |
| Synthetic delivery lifecycle | separate QA-only RLS tables in 018; `phase13-delivery-qa.ts` | claim/lease, consumer dedupe, backoff 1/2/4, retry, ack, terminal dead-letter, no network |
| Historical upgrade | `phase13-upgrade.pg.test.ts` | 016→017→018 and populated 017→018 preservation of old ledger/disabled outbox |
| Browser QA foundations | `tests/browser/phase13.spec.ts` | real React/Fastify/PostgreSQL, mobile, keyboard, zoom, locale direction, reduced motion, tenant switch |
| Full provenance | `.github/workflows/phase13.yml` | Gate must succeed at **exact last commit**; earlier pass is insufficient |

**Verification status:** PENDING exact-head comprehensive GitHub-hosted CI for this rework. Passing earlier run #38040961546 only certifies the earlier SHA. No claim of final acceptance until review of actually executed tests and all historical regressions.

## Production deployment restrictions
No customer scanning, production permits, invoice authority, payment lifecycle, Host JWT minting, public npm publishing, automatic merge or release. PR stays OPEN/DRAFT/UNMERGED for independent security acceptance. The complete historical test logs, failures and source hashes are inspected in GitHub Actions; passing CI does not certify full original product requirements.
