# Phase 06 — authorization and fixture execution threat model

## Authority split

Main Platform Host authority is NOT FROZEN and remains BLOCKED. No real Host JWT/JWKS, delegated memberships, ownership attestations, production permits, egress policy, vault access, commercial entitlements, canonical findings, or RetestVerificationAuthority exists in this isolated module. The CI synthetic issuer uses a distinct testing key, a test-only issuer and an in-process fixture audience. Production initialization fails closed. No registered API URL, imported OpenAPI servers field, customer-approved flag, client field, or successful onboarding challenge confers real scanning rights.

## Trust boundaries

| Boundary | Threat | Control | Qualification |
| --- | --- | --- | --- |
| Browser -> service | impersonated authority or synthetic permit | distinct trusted test-only authority key, strict payload keys and server-issued permits | negative Fastify/Chromium tests |
| Tenant -> database | cross-tenant scope/permit/receipt leakage | composite tenant foreign keys, FORCE RLS | real PostgreSQL privilege and tenancy tests |
| Scope -> permit | tampered issuer, audience, method, target or spec | HMAC-SHA256, canonical encoding, constant-time MAC, binding and revision checks | cryptographic tests |
| Permit -> worker | TOCTOU after revocation or target change | transactional per-operation revalidation, stop and permit row locks | PostgreSQL race qualification |
| Worker -> transport | SSRF, redirects, customer credentials | fixed in-memory Fastify inject, GET/HEAD two fixed paths, no network transport | fixture unit tests and Chromium request checks |
| Worker -> budget | concurrent overspending, repeated delivery | PostgreSQL locked permit row, immutable ledger identity, reserved/consumed semantics | multi-session PostgreSQL contention |
| Private queue -> worker | duplicate claims and stale lease | existing claim tokens, durable worker role boundary, checked lease ownership | competing worker and stale lease tests |
| Stop -> worker | unauthorized restart and in-flight execution | test-authority-only stop, revocation; effective at evaluation transaction boundary | cancellation/stop tests |
| Report -> customer | synthetic success mistaken for live VAPT | immutable PT-specific receipts and report; zero network requests; no canonical findings | E2E provenance |
| Incident -> audit | history rewritten | immutable append-only event/receipt/report tables | attempted UPDATE/DELETE negative tests |

## Provisional safety policy

Execution profile SYNTHETIC_PT_READ_ONLY uses methods GET and HEAD only, against billing-safe-v1 fixture operations /bills and /status. OPTIONS is not allowed. POST/PUT/PATCH/DELETE/TRACE/CONNECT/custom methods are not allowed. Safe HTTP semantics on a real customer API are never assumed. MAX 30 evaluations, 2 permit concurrent jobs, 20 per-minute approvals, 30-second job deadline. Exact enacted constraints and limits live in database constraints and server validation, not merely in the browser.

Authorization separates customer-proposed scope, independently requested approval, signed synthetic permit, and the worker's current per-operation transaction decision. A permit's signature alone is insufficient. Target active state and revision, selected immutable specification version, operation identity, fixture, budget, cancellation/revocation, expiry, and global stop must agree.

## Retry / failure policy

Evaluation reservation is durable before fixture admission. A reservation can become uncertain if execution progress is lost; an uncertain operation is not retried and still consumes permit capacity. A revoked/stopped evaluation must not gain a fresh budget allocation. Receipt publication is bounded and append-only; no status code creates a vulnerability finding.

Authorization is checked at initial admission, private worker claim, and before each evaluation, and reevaluated after controlled state transitions. Stop can prevent the next operation, but this phase must not claim instantaneous interruption of arbitrary already-running synchronous code.

## Real Host blockers

1. Trusted JWT/JWKS and delegated tenancy authority.
2. Canonical customer ownership and authorized environments.
3. Host-issued real permits and revocation verification.
4. Trusted, scoped, observed outbound HTTP egress and credential isolation.
5. Commercial entitlements and quotas.
6. Canonical vulnerability promotion and immutable RetestVerificationAuthority.
7. Finalized plugin and cross-product integration contracts.

These blockers must never be labelled implemented by the isolated test-only issuer. A CI PASS never means VERIFIED_FIXED, and missing findings do not mean SAFE.