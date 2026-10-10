# Phase 13 — Security and requirement closeout audit (isolated, non-production)

**Scope:** accepted Phase12 commit `31b8c402524dcc5e6d0c7fecf3a7c5b1262d4e6b`; existing Phase13 Draft PR #14. This document is committed with the implementation and becomes qualified only when GitHub Actions runs on **this containing commit**. The PR's final engineering evidence comment and description carry the exact commit SHA and successful job/run identifiers; avoid treating earlier-sha CI as evidence for later changes.

**Evidence baseline (historical, not final for this document):** exact SHA `e3a89be7a2a15bb3827439f562bbf46ee277f6e1`, run [#38038050938](https://github.com/mkalyankumar903-hash/API-security-family/actions/runs/38038050938), full job `114172534752`: 135 unit checks, 154 PostgreSQL, 2 actual PDF parser, 40 Chromium, ESLint/strict TS/build and SDK dry-run package PASS. This SHA preceded the delivery-state/feature-catalog/UX enhancements. The standalone historical job was skipped by design; its tests ran in comprehensive Full. The latest authoritative final-sha evidence must be checked on GitHub, not inferred from this older snapshot.

## Requirements, source, independently executable evidence

| # | Requirement | Source and verification | Status |
|---|---|---|---|
| 1 | Typed Host adapters and trust separation | `packages/contracts/src/commercial-v13.ts`; contract negative tests. Production Host bindings absent. | IMPLEMENTED_AND_VERIFIED (types); live connection HOST_BLOCKED |
| 2 | Signed entitlement expiry, revocation, revision | `commercial-v13.ts`, `phase13.ts`; strict event and revision PG tests. | IMPLEMENTED_AND_VERIFIED (synthetic) |
| 3 | Tenant quota/capacity decisions | PostgreSQL advisory locks, tenant-RLS projection and hard denial on `/v13/decisions`. One observation meter only. | PARTIALLY_IMPLEMENTED (multi-meter entitlements absent) |
| 4 | Source-backed idempotent metering | Immutable Phase11 successful report FK, fingerprint, unique source and idempotency. Missing source rejected. | IMPLEMENTED_AND_VERIFIED (report-only) |
| 5 | Reserve/settle/expire/release/recovery | `phase13.ts`, PostgreSQL TTL/race/replay tests. Crash failover not separately stress-tested. | PARTIALLY_IMPLEMENTED (crash-specific fault injection absent) |
| 6 | Immutable ledger and signed correction events | Migration 017; signed correction, replay, bounds, cross-tenant negatives. | IMPLEMENTED_AND_VERIFIED |
| 7 | Concurrent transaction-safe quota | `pg_advisory_xact_lock`, simultaneous reserve tests, revocation/admission race. | IMPLEMENTED_AND_VERIFIED |
| 8 | Signed event tamper/replay and key rotation | Strict raw-byte MAC, clock skew/expiry, inbox event dedupe, test keyring unknown/expired negatives. | IMPLEMENTED_AND_VERIFIED (CI only) |
| 9 | Independent reconciliation and watermarks | Separate signed CI accounting snapshots, immutable mismatch history and signed corrections. Real external accounting absent. | IMPLEMENTED_AND_VERIFIED (synthetic); live HOST_BLOCKED |
| 10 | Transactional inbox/outbox | Same-transaction ledger/outbox and inbox dedupe; immutable outbox state `DISABLED`, attempt_count=0. No callback dispatcher. | PARTIALLY_IMPLEMENTED (delivery disabled by design) |
| 11 | Fastify API and OpenAPI | `packages/service/src/phase13.ts`, `docs/phase13-openapi.yaml`; versioned GET endpoints and schema contract. | IMPLEMENTED_AND_VERIFIED (isolated read-only) |
| 12 | SDK and packaging | `packages/sdk/src/v13.ts`; caller-supplied bearer; private Node ESM declaration build, dry-run pack, transport/error/paging tests. | IMPLEMENTED_AND_VERIFIED |
| 13 | React customer workspace | `Phase13Workspace.tsx`, browser Phase13 real React–Fastify–Postgres UI. | IMPLEMENTED_AND_VERIFIED (synthetic) |
| 14 | Migration 017, FORCE RLS, privileges | 7 tables, RLS/FORCE, worker denied, immutable triggers. | IMPLEMENTED_AND_VERIFIED |
| 15 | Populated 016→017 historical upgrade | `tests/phase13-upgrade.pg.test.ts`; original reports, queue, targets, snapshots preserved. | IMPLEMENTED_AND_VERIFIED |
| 16 | Phase00–12 security invariants | Full historical PostgreSQL, 40 Chromium and PDF parser regressions. | IMPLEMENTED_AND_VERIFIED |
| 17 | Production Host authorization and fail-closed | `HOST_AUTHORITY_NOT_CONFIGURED` decisions always deny; Main Platform tenant, JWKS and billing not supplied. | HOST_BLOCKED (boundary implemented) |
| 18 | Responsive, keyboard and localization foundations | Semantic labels/captions, overflowing table wrapper, explicit QA pseudo-RTL and pseudo-expanded test. No customer translations/certification. | PARTIALLY_IMPLEMENTED |
| 19 | No-store and tenant isolation | Fastify no-store GET hook, tenant-scoped RLS readbacks, forbidden cross-tenant HTTP. | IMPLEMENTED_AND_VERIFIED |
| 20 | Exact final HEAD GitHub Full qualification | `.github/workflows/phase13.yml`, PR #14 evidence comment. Must match containing SHA. | VERIFY_FINAL_SHA_IN_PR |

## Security review
- **No real Host:** no JWT/JWKS, membership, real subscriptions, merchant callbacks or payments. Development tokens and CI HMAC fixture keys are never customer authorization.
- **No new scanning authority:** every `/v13/decisions` response returns `allowed:false`. A commercial entitlement does not mint a Phase06 signed permit, authorize a network, alter a finding or set `VERIFIED_FIXED`. UNKNOWN ≠ SAFE; NO EVIDENCE ≠ SAFE; FIX_CLAIMED ≠ VERIFIED_FIXED.
- **Evidence accounting:** only distinct already-successful immutable Phase11 reports meter as one **non-billable observation**, with synthetic-only consent. No claim that legacy Phase00–12 assessment routes are commercially gated. Failed/cancelled/no-report operations have no billable usage.
- **Feature catalog:** versioned definitions do NOT mean multiple active meters. Other offline and governed PT features are explicitly `DISABLED`, not chargeable or scan-enabled. Multi-feature source-derived accounting remains independently executable follow-up if required by original master scope; do not classify as Host blocked.
- **Revocation/expiry:** admission and settlement re-check current test entitlement while serializing within tenant-feature advisory transaction; revoked states cannot become successful new usage.
- **Inbox/outbox:** signed event inbox and usage outbox are durable, immutable, tenant-isolated. Explicit DB delivery-state constraints keep all transmissions disabled; no retry scheduler, URL, leases or delivery credentials are configured. Thus delivery reliability beyond DISABLED remains unqualified rather than falsely implemented.
- **Reconciliation:** independently signed CI external observations can produce MATCHED/MISMATCH; absent Host snapshot remains PENDING_EXTERNAL_AUTHORITY. Neither compares against an actual invoice.
- **UX:** pseudo-locale modes are test fixtures, not translations. No WCAG certification or production usability sign-off.
- **Known engineering gaps:** multi-feature active accounting, process-crash fault-injected ledger recovery, and actual disabled-outbox→delivery lifecycle are NOT declared fully implemented. Outbound integration additionally needs approved Host envelope, trust roots, delivery security/authorization and legal business arrangements.

## Production deployment restrictions
No customer scanning, production permits, invoice authority, payment lifecycle, Host JWT minting, public npm publishing, automatic merge or release. PR stays OPEN/DRAFT/UNMERGED for independent security acceptance. The complete historical test logs, failures and source hashes are inspected in GitHub Actions; passing CI does not certify full original product requirements.
