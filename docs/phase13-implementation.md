# Phase 13 — Isolated commercial integration (engineering work, NOT Host authorization)

This phase builds a test-only, tenant-scoped, commercially inert foundation on accepted Phase 12. Host identity, real entitlements, payment, target ownership, live permits, canonical findings and RetestVerificationAuthority remain wholly Main Platform owned. Commercial permission never authorizes scanning.

## Implemented boundaries
- Versioned, strict signed test-only entitlement-event contract and five Host adapter interfaces; without approved Host trust configuration production fails closed.
- Migration 017 introduces six tenant-isolated FORCE RLS tables (entitlement events, reservations, usage ledger, event inbox, outbox, reconciliation). Privileged queue worker has no grants. Immutable records reject UPDATE/DELETE. Reservation state mutation is restricted to allowed transitions.
- `IMMUTABLE_REPORT_OBSERVED` is a single non-billable **observation unit** tied to an existing, fingerprinted, immutable Phase 11 report. A render/button click does not meter usage. No historical usage is backcharged.
- A real PostgreSQL transaction takes a tenant+feature advisory lock; deduplicated reservations, bounded units, expiry and settlements create exactly one immutable ledger row and exactly one unsent outbox row. Database clock governs the month and expiry.
- `/v13` read APIs return only session-bound, tenant-RLS projections. Every decision is `allowed:false` until real Host authority is approved. Existing accepted Phase 00–12 routes stay synthetic-only and are **not claimed to be under commercial quotas**.
- SDK provides a typed GET-only API facade with caller-injected tokens, origin validation, timeout/AbortSignal, bounded pagination and structured errors. No npm publish; no SDK-created credentials.
- No real payment, invoice, settlement, provider callbacks, external transmission, customer execution or VERIFIED_FIXED write paths.

## Unresolved / scope limitations
- Host adapter types are **not connected** to approved deployed Host authority/JWKS, billing or customer tenant memberships.
- Current entitlement issuer is strictly `lumicsec-ci-synthetic-v13` (never production). Host entitlement verification and production operational authorization remain **HOST_BLOCKED**.
- Current ledger supports only a narrow source-confirmed immutable report meter, not every candidate usage category.
- Reconciliation with no independent signed external snapshot remains `PENDING_EXTERNAL_AUTHORITY`; a local counter must not be treated as a Host invoice.
- Outbox is durable **but delivery intentionally disabled**. No actual callbacks or live signing key rotation.
- Current UI is English with existing Phase 12 QA pseudo-locales retained; no translation or WCAG certification is claimed.

## Acceptance and source map
| Requirement | Source | Evidence | Status |
|---|---|---|---|
| Isolated typed authority contracts | `packages/contracts/src/commercial-v13.ts` | `tests/phase13-contract.test.ts` | IMPLEMENTED_NOT_YET_VERIFIED |
| Real RLS migration | `packages/database/migrations/017_phase13_commercial_entitlements_usage.sql` | `tests/phase13.pg.test.ts` | IMPLEMENTED_NOT_YET_VERIFIED |
| Bounded report quota and ledger | `packages/service/src/phase13.ts` | `tests/phase13.pg.test.ts` | IMPLEMENTED_NOT_YET_VERIFIED |
| Read-only API and SDK | `packages/service/src/phase13.ts`, `packages/sdk/src/v13.ts` | unit/PG/browser | IMPLEMENTED_NOT_YET_VERIFIED |
| Customer workspace | `packages/ui/src/Phase13Workspace.tsx` | `tests/browser/phase13.spec.ts` | IMPLEMENTED_NOT_YET_VERIFIED |
| Live Host identity and billing | Main Platform not frozen | Missing external authority | HOST_BLOCKED |
| Public npm release, deployment | Phase15 handover | Not authorized | OUT_OF_SCOPE |

No immutable historical migrations modified. This document is not an assertion that GitHub-hosted tests have passed.
