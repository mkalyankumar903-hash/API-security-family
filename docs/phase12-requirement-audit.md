# Phase 12 — source-to-acceptance engineering evidence matrix

## Provenance and hard boundaries

- Repository: `mkalyankumar903-hash/API-security-family`.
- Accepted Phase 11 source: `141283396cba29bed1ac9441cff03f755bf5c0f6`; accepted full CI [#38022744056](https://github.com/mkalyankumar903-hash/API-security-family/actions/runs/38022744056).
- Existing stacked Phase 12 branch: `work/phase12-unified-ux-reports-readonly-ai`; existing Draft PR [#13](https://github.com/mkalyankumar903-hash/API-security-family/pull/13).
- Initial Phase 12 HEAD `591d950dc1b3f4109309cf4008ea34b5c896ad5a`, 32 commits, 24 changed files; preserved non-destructively.
- Targeted Phase 12 CI [#38026982201](https://github.com/mkalyankumar903-hash/API-security-family/actions/runs/38026982201): all three Fast, PostgreSQL, Chromium jobs SUCCESS after two original lint recoveries (at `5d17a0461a76f817fc6408f7514a83e03bd95939`). This is an earlier checkpoint, **not final-head acceptance**.
- No customer network scanning, no Host impersonation, no invented real provider, no production deploy, and no canonical `VERIFIED_FIXED` promotion.

## Requirement-to-source-to-execution map

| Requirement / acceptance | Implementation evidence | Executable evidence and status |
|---|---|---|
| Preserve Phase 00–11 accepted behavior | The accepted Phase 11 source is ancestor; `packages/service/src/app.ts` registers new, separately namespaced `/v12` APIs; existing workers and signature authority untouched | `npm run test:pg`, `npm test` and Phase 00–11 Chromium specs preserved in `.github/workflows/phase12.yml` historical/full jobs; **historical final-head CI still REQUIRED** |
| Unified API targets/specification/inventory context | `packages/ui/src/AssessmentApp.tsx`, existing `TargetOnboarding`, `Phase12Workspace`, grouped keyboard-accessible navigation | Phase 12 Chromium tests verify target selection, refresh, identity switch, narrow viewport; prior Phase 00–11 browser specs retained |
| Authorized organization/target overview | `phase12.ts` `/v12/overview`: tenant-bound PostgreSQL counts, no fabricated finding counts | `tests/phase12.pg.test.ts` and `tests/browser/phase12.spec.ts` |
| Historical assessment list, state, modes, and selection | `phase12.ts` `/v12/assessments`; `Phase12Workspace.tsx` read-back, bounded pagination and UUID restore | PostgreSQL tenant-authorization, Chromium refresh and unauthorized identity switch |
| Cross-assessment findings filtering | `phase12-findings.ts` target/assessment/source/annotation/date/rule filters; `Phase12FindingExplorer.tsx` source and triage UI | PostgreSQL invalid filters, cross-tenant negatives; Chromium server-filtered explorer and provenance drill-down |
| Immutable finding detail and redacted evidence | `/v12/reports/:id/findings/:key`, `/v12/reports/:id/evidence/:key`; no raw confidential bodies or live validation claim | `phase12.pg.test.ts` correlation/detail/provenance negatives; source fingerprint and tenant checks |
| Truthful coverage and unknowns | `/v12/reports/:id/coverage` and `presentVaptReport`; actual numerator/denominator, `unknownIsSafe=false`, `verifiedFixed=false` | PostgreSQL coverage contract and unit security invariants |
| Comprehensive immutable report presentation | `phase12.ts` derives only from fingerprint-valid Phase 11 `api_vapt11_reports`, bounded redacted projections | `phase12-contract.test.ts`; PostgreSQL read-back and tamper negatives |
| Actual advanced PDF reports | `phase12-pdf.ts` uses headless Chromium, escaping, 20 numbered evidence sections, size/concurrency limits, disabled JS/external resources; tenant branding | `phase12-pdf.test.ts`, `phase12-pdf-render.test.ts` with independent Poppler parser, multipage Unicode, and real Chromium PDF download. **Actual content is source-derived; no invented real-world pentest findings** |
| JSON export | `/v12/reports/:id/export.json` bounded, authenticated, redacted, versioned and no-store | PostgreSQL export fingerprint/authorization; actual Chromium download |
| Report generation/view/export audit | `api_v12_report_audit`, append-only triggers; PDF requested/generated events distinguished; no audit deletion | PostgreSQL audit history and update/delete negative tests |
| Versioned finding triage, no finding mutation | `phase12-workflows.ts`, `api_v12_annotations`, optimistic concurrency under transaction advisory locking; UI | Real PostgreSQL conflicting concurrent writes, immutable history, Chromium triage; `FIX_CLAIMED` **never** `VERIFIED_FIXED` |
| Tenant-controlled branding | `api_v12_branding`, restricted hex color/display title, expectedVersion, PDF presentation integration | Real PostgreSQL concurrent brand version conflict and cross-tenant isolation; Chromium branding-to-PDF flow |
| Controlled sharing | `api_v12_shares`; bearer required for reads, tenant RLS, expiry, revocation, idempotency and immutable safety | PostgreSQL actual races, expiry, 404 foreign tenant, stale/revoked shares; Chromium create/use/revoke. **No anonymous/public share authority claimed** |
| Optional AI explanation | `/v12/ai/capabilities` and `/v12/ai/explain` intentionally return **DISABLED/503**; no model provider, tools, scan or mutations | 20 adversarial prompts; assertions no external provider calls, no worker/permit/audit mutation; Chromium disabled state |
| Architecture and API contracts | `docs/phase12-openapi.yaml` documents 21 isolated versioned operations; validated against `phase12.ts`, `phase12-workflows.ts`, `phase12-findings.ts` | `phase12-openapi.test.ts`; strict typed contracts via `npm run typecheck` |
| Locale and RTL foundation | `phase12-locale.ts` English complete, explicit **QA-only** pseudo-LTR and pseudo-RTL; UTC formatting. No fake customer translations | `phase12-locale.test.ts`, Chromium RTL/keyboard/viewport checks. **Professional translations and formal WCAG certification are NOT claimed** |
| Accessible / responsive navigation | Semantic table headers, labels, keyboard focus, reduced motion, CSS mobile overflow safeguards in `styles.css` | Chromium viewport 390px/768px, keyboard focus and control labels; **not a substitute for full WCAG 2.2 AA manual assistive-technology audit** |
| Fresh schema 001→016 | `packages/database/migrations/016_phase12_unified_experience_reports.sql`, `packages/database/src/index.ts` migrations, FORCE RLS, private app role grants | PostgreSQL 16 fresh migration, policy checks; separate clean browser DB |
| Populated historical upgrade 015→016 | additive migration 016, no mutation of Phase 11 canonical reports, queuing or permit data | `tests/phase12-upgrade.pg.test.ts` creates independent database, snapshots populated reports, assessments, queues and provenance before/after |
| Independently isolated CI jobs | `.github/workflows/phase12.yml` Fast, targeted PostgreSQL and Chromium + full historical regression + dedicated `[phase12-full]` job | Historical and final-head comprehensive gates must actually execute and be checked at exact final SHA |
| Host delegated identity / real client authorization / public share | Not supported by independent API Family: requires future frozen Main Platform Host authority contract | **HOST-BLOCKED**, excluded rather than mocked |
| Live customer scanning / production `VERIFIED_FIXED` | Intentionally prohibited by current signed-scope synthetic-only product boundary | **OUT OF SCOPE / PROHIBITED**, not an acceptance defect |

## Must be verified before engineering closeout

1. GitHub-hosted exact-head Fast/PG/Chromium targeted qualification succeeds after final fixes.
2. Phase 00–11 historical PostgreSQL and Chromium regressions run on GitHub-hosted infrastructure on the preserved Phase 12 code without weakening old assertions.
3. **One authoritative [phase12-full]** executes lint, TypeScript, complete unit/contract suite, Phase 00–11 PostgreSQL, Phase 12 real PostgreSQL and upgrade, old historical Chromium, Phase 11 Chromium, Phase 12 actual PDF/Chromium tests with separate clean databases.
4. GitHub run details and logs prove the final Full job, actual test counts and no skipped required gates; compare checked-out `git rev-parse HEAD`, branch head and PR head.
5. Update existing Draft PR #13 with exact evidence and independent reviewer limitations. Do not merge, deploy or start Phase 13.

**These are explicit acceptance gates, not assertions of completion.**
