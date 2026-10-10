# Phase 12 requirement-to-source audit (initial checkpoint)

Base: `141283396cba29bed1ac9441cff03f755bf5c0f6`, Phase 11 Full CI #38022744056 SUCCESS. Phase 12 is independent development; no phase acceptance implied.

| Scope | Reusable source | Initial status | Acceptance still needed |
|---|---|---|---|
| Target context, specifications, inventory | `AssessmentApp.tsx`, `onboarding.ts`, `discovery.ts` | REUSABLE_WITH_INTEGRATION | Coherent routed shell, refresh state and tenant switch |
| Legacy assessment list/findings/detail/coverage | `unified.ts` | REUSABLE_WITH_INTEGRATION | Unified filtering, provenance and workflow |
| Synthetic PT orchestration | `orchestrator.ts`, `pt-product.ts` | IMPLEMENTED_AND_QUALIFIED in Phase 11 baseline | No new execution authority |
| Composite VAPT assessment/report/history/compare | `autonomous-vapt.ts`, `api_vapt11_reports` | IMPLEMENTED_AND_QUALIFIED in Phase 11 baseline | Presentation, accessible UI, new report suite |
| First read-only presentation/overview/JSON facade | `phase12.ts` | PARTIALLY_IMPLEMENTED / NOT VERIFIED | GitHub-hosted CI, E2E, pagination and full product UX |
| Customer annotations and audit | No Phase12 storage yet | MISSING | Migration 016, FORCE RLS, optimistic locking, security tests |
| PDF generation | No server PDF export | MISSING | Maintained library, reproducible lockfile, actual parser + Chromium tests |
| Tenant-only sharing, branding | No Phase12 records | MISSING | Migration, expiry, revocation, audit, race tests |
| Optional read-only AI | No real provider authorized | DISABLED by design | AI schema/authorization and prompt-injection negatives; real provider unavailable |
| Production Host delegated identity / public share | No frozen Host interface | HOST_BLOCKED | No synthetic public authorization |
| i18n, WCAG 2.2 AA, responsive UX | Existing React components | PARTIALLY_IMPLEMENTED | Stable keys, keyboard/screen-reader/viewport checks |
| Fresh 001→016 and populated 015→016 | Migrations 001–015 accepted | MISSING | Real PostgreSQL 16 preservation and race qualification |
| Historical 00–11 regressions | `phase11.yml`, prior tests | QUALIFIED_AT_ACCEPTED_BASE_ONLY | Exact new final HEAD required |
| Comprehensive final-head Phase12 Full CI | None | NOT_VERIFIED | Full workflow, actual executed SHA and job result |

Invariants: `SPEC_ONLY NETWORK REQUESTS = 0`; `UNKNOWN != SAFE`; `AI EXPLANATION != SECURITY EVIDENCE`; `SHARING != AUTHORIZATION EXPANSION`; `NO LONGER OBSERVED != VERIFIED_FIXED`; all customer runtime verification and verified-fixed claims remain false.

This document is an engineering checkpoint, not a completion/acceptance matrix. Failed or unverified gates must remain open.
