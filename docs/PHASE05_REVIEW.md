# Phase 05 — API Security Assessment: Verified Source Scope and Review Gaps

## Exact boundary
Repository: mkalyankumar903-hash/API-security-family
Base: cbfca77fd26aad9ef484a7029fd074ce1cb730c4 (Phase04; GitHub-hosted Full CI 37911623731 PASS).
Branch: work/phase05-complete-api-assessment, stacked from Phase04, without merges.
Host integration: NOT FROZEN; no production JWT/JWKS, owner authority, credentials, network permits, canonical finding authority or RetestVerificationAuthority.
Only offline document analysis and fixed in-process synthetic fixture evaluation are authorized. `SPEC_ONLY`: methods = [], maxRequests = 0.

## API product architecture
Existing React AssessmentApp -> existing Target Onboarding and Discovery -> existing inventory-v1 / auth-fixture-v1 configuration -> Fastify -> tenant-scoped PostgreSQL (FORCE RLS) -> private worker -> immutable evidence/findings/reports.
Phase05 adds a read-only, tenant-scoped projection across **existing** authorities. It never creates a second queue, engine, finding authority, or mutable report store.

The new customer workspace `UnifiedAssessment` displays engine choices with actual applicability, launches existing supported configuration controls, and reads persisted historical runs, findings, evidence, coverage, immutable report provenance, JSON export and conservative comparison. These are integration features, not Host integration.

## Versioned endpoints
- `GET /v5/engines`: engine capability labels, SPEC_ONLY and no-network restrictions.
- `GET /v5/assessments`: bounded 1-100 rows, offset <= 1m, target/spec/engine/status/date/search filters.
- `GET /v5/assessments/:id`: tenant-bound run state.
- `GET /v5/assessments/:id/findings`: server-side bounded category, rule, operation, confidence, impact, search filters.
- `GET /v5/assessments/:id/findings/:findingId`: redacted persisted evidence and review guidance.
- `GET /v5/assessments/:id/coverage`: stored per-rule execution and explicit limitations.
- `GET /v5/assessments/:id/report`: immutable report with a Phase05 envelope, raw/normalized fingerprint provenance.
- `GET /v5/assessments/:id/export`: capped 1 MiB response, tenant checked, no-store attachment.
- `POST /v5/assessments/compare`: same-target, same-engine, completed immutable runs. Fail closed on incompatible rule coverage or missing stable correlation. No longer observed != VERIFIED_FIXED.

Actual assessment creation remains exclusively on the preserved `/v1`, `/v3` and `/v4` entrypoints; the unified workspace routes customers to those existing validated controls. No new execution authority is introduced.

## Existing engine matrix
| Engine | Runtime | Data | Honest scope |
| --- | --- | --- | --- |
| legacy-v1 | Existing private worker | Historical compatible OpenAPI/Swagger | Specification-only; preserved compatibility, no synthetic fixture |
| inventory-v1 | Existing private worker | Immutable phase02-v1 inventory of OpenAPI 3.0/3.1, Swagger 2, Postman 2.1 | Deterministic declarations; 28 rules, 15 executable pathways, 13 intentionally skipped (and format-specific SKIPPED) |
| auth-fixture-v1 | Existing private worker | Versioned inventory + test-only validated profile | Trusted in-process fixture results; *never* customer authenticated scanning |

## Original 28 detection rules — SOURCE-VERIFIED inventory-v1
These statuses describe engine implementation capability; a supported rule may be SKIPPED for a particular format. The Phase05 unified projection does not change inventory-v1 rule semantics.

| Rule | Engine availability | Evidence limitation / reason |
| --- | --- | --- |
| API03_AUTH_UNDECLARED | DECLARATION-EVALUATED | Missing declarations never prove absent runtime authentication. |
| API03_AUTH_EXPLICIT_NONE | DECLARATION-EVALUATED | Does not confirm runtime anonymous access. |
| API03_AUTH_SENSITIVE_ROUTE | DECLARATION-EVALUATED | Route naming is a heuristic, not evidence of BOLA or BFLA. |
| API03_AUTH_WRITE_PUBLIC | DECLARATION-EVALUATED | No mutation is executed or confirmed accessible. |
| API03_AUTH_OVERRIDE_WEAKENS | SKIPPED / UNSUPPORTED | Inherited requirements cannot be safely reconstructed. |
| API03_AUTH_APIKEY_QUERY | DECLARATION-EVALUATED | The importer never accesses or stores key values. |
| API03_AUTH_BASIC | DECLARATION-EVALUATED | Does not prove insecure transport. |
| API03_AUTH_OAUTH_SCOPE | SKIPPED / UNSUPPORTED | OAuth flow scope definitions are unavailable. |
| API03_AUTH_UNKNOWN_SCHEME | SKIPPED / UNSUPPORTED | Invalid schemes are already rejected during import. |
| API03_AUTH_INCONSISTENCY | SKIPPED / UNSUPPORTED | Conservative related-operation inference unavailable. |
| API03_BODY_SCHEMA_MISSING | DECLARATION-EVALUATED | Schema enforcement remains unknown. |
| API03_STRING_NO_BOUNDS | SKIPPED / UNSUPPORTED | Maximum/minimum length metadata unavailable. |
| API03_ARRAY_NO_BOUNDS | SKIPPED / UNSUPPORTED | Array size bounds unavailable. |
| API03_NUMBER_NO_RANGE | DECLARATION-EVALUATED | An importer-normalized constraint indicator, not validation of runtime enforcement. |
| API03_OBJECT_PERMISSIVE | SKIPPED / UNSUPPORTED | Object additionalProperties semantics unavailable. |
| API03_PATH_PARAMETER_WEAK | DECLARATION-EVALUATED | Does not prove missing runtime validation. |
| API03_ADDITIONAL_PROPERTIES | SKIPPED / UNSUPPORTED | additionalProperties is not projected. |
| API03_REQUEST_SENSITIVE_FIELD | DECLARATION-EVALUATED | Names alone are not proof of a vulnerability. |
| API03_ERROR_RESPONSE_GAPS | SKIPPED / UNSUPPORTED | Response status-only declarations unavailable. |
| API03_RESPONSE_SENSITIVE_FIELD | DECLARATION-EVALUATED | Field names do not prove data leakage. |
| API03_EXAMPLE_CREDENTIAL | SKIPPED / UNSUPPORTED | Raw example values deliberately unavailable. |
| API03_DESCRIPTION_SENSITIVE_EXAMPLE | SKIPPED / UNSUPPORTED | Raw descriptions deliberately unavailable. |
| API03_RESPONSE_SCHEMA_INCONSISTENT | SKIPPED / UNSUPPORTED | Insufficient comparability evidence. |
| API03_HTTP_SERVER | DECLARATION-EVALUATED | Does not prove the service accepts cleartext traffic. |
| API03_UNRESOLVED_SERVER | DECLARATION-EVALUATED | No DNS or network resolution attempted. |
| API03_DEPRECATED_OPERATION | DECLARATION-EVALUATED | Deprecated does not mean vulnerable. |
| API03_DEPRECATED_AUTH_SCHEME | DECLARATION-EVALUATED | Basic authentication is only a heuristic for legacy schemes. |
| API03_UNSUPPORTED_SECURITY_METADATA | SKIPPED / UNSUPPORTED | Unknown security metadata must be reported as coverage, not a finding. |

Do NOT declare all 28 implemented. No BOLA/BFLA/IDOR/SQL injection/SSRF findings may be inferred from names or synthetic fixture deviations.

## Phase 05 additional isolated normalization and engine (implemented, qualification separately required)
- Forward-only migration `008_phase5_rich_offline.sql`: new `api_rich_inventories` with FORCE RLS, immutable trigger and least-privilege grants. Never rewrites `phase02-v1` JSON, assessments or reports. Historical versions remain v1; no invisible backfill.
- New-import-only `phase05-v2` offline metadata: explicit operation override semantics, OAuth scope-name declarations, inline parameter string/array bounds, inline request-body explicit additionalProperties and error-response status declarations. Secrets, raw examples, bodies and descriptions are not projected.
- Separate `inventory-v2` engine reuses 28 canonical rule IDs, deterministic canonical hashes, six new evaluation paths, existing `api_assessments` transactional enqueue, private worker and immutable evidence/report publication. The original `inventory-v1` and `auth-fixture-v1` execution semantics remain unchanged.
- Versioned `POST /v5/targets/:targetId/assessments` supports v1/v2 SPEC_ONLY with strict body schema and existing idempotency/tenant/target lifecycle checks; Phase04 synthetic authenticated creation stays on its stronger profile+attestation-specific contract. `POST /v5/assessments/:id/cancel` delegates to the original cancellation authority. There is no second queue or production network permit.
- Unified React workspace supports engine selection, new-version refresh, v1/v2 queue start, cancel, persisted findings, evidence, coverage, export, history and conservative comparisons. Internal contract intentionally refuses synthetic-fixture launches without the existing Phase04-specific identity/profile validation.
- Coverage claims must be per-run: **15 rules had v1 evaluators**, **6 additional rule families are evaluable in v2 when required evidence exists**, and **7 stay intentionally unsupported**. A rule with unsupported references or ambiguous semantics is SKIPPED, even if it has a v2 evaluator.

### Phase05-v2 28-rule evidence matrix
| Rule | New-engine catalog availability | Technical provenance or skip reason |
| --- | --- | --- |
| API03_AUTH_UNDECLARED | SUPPORTED (v1 inherited) | Missing declarations never prove absent runtime authentication. |
| API03_AUTH_EXPLICIT_NONE | SUPPORTED (v1 inherited) | Does not confirm runtime anonymous access. |
| API03_AUTH_SENSITIVE_ROUTE | SUPPORTED (v1 inherited) | Route naming is a heuristic, not evidence of BOLA or BFLA. |
| API03_AUTH_WRITE_PUBLIC | SUPPORTED (v1 inherited) | No mutation is executed or confirmed accessible. |
| API03_AUTH_OVERRIDE_WEAKENS | SUPPORTED (v2 extension) | New-import-only redacted declarations; fail closed on missing metadata |
| API03_AUTH_APIKEY_QUERY | SUPPORTED (v1 inherited) | The importer never accesses or stores key values. |
| API03_AUTH_BASIC | SUPPORTED (v1 inherited) | Does not prove insecure transport. |
| API03_AUTH_OAUTH_SCOPE | SUPPORTED (v2 extension) | New-import-only redacted declarations; fail closed on missing metadata |
| API03_AUTH_UNKNOWN_SCHEME | SKIPPED (unchanged) | Invalid schemes are already rejected during import. |
| API03_AUTH_INCONSISTENCY | SKIPPED (unchanged) | Conservative related-operation inference unavailable. |
| API03_BODY_SCHEMA_MISSING | SUPPORTED (v1 inherited) | Schema enforcement remains unknown. |
| API03_STRING_NO_BOUNDS | SUPPORTED (v2 extension) | New-import-only redacted declarations; fail closed on missing metadata |
| API03_ARRAY_NO_BOUNDS | SUPPORTED (v2 extension) | New-import-only redacted declarations; fail closed on missing metadata |
| API03_NUMBER_NO_RANGE | SUPPORTED (v1 inherited) | An importer-normalized constraint indicator, not validation of runtime enforcement. |
| API03_OBJECT_PERMISSIVE | SKIPPED (unchanged) | Object additionalProperties semantics unavailable. |
| API03_PATH_PARAMETER_WEAK | SUPPORTED (v1 inherited) | Does not prove missing runtime validation. |
| API03_ADDITIONAL_PROPERTIES | SUPPORTED (v2 extension) | New-import-only redacted declarations; fail closed on missing metadata |
| API03_REQUEST_SENSITIVE_FIELD | SUPPORTED (v1 inherited) | Names alone are not proof of a vulnerability. |
| API03_ERROR_RESPONSE_GAPS | SUPPORTED (v2 extension) | New-import-only redacted declarations; fail closed on missing metadata |
| API03_RESPONSE_SENSITIVE_FIELD | SUPPORTED (v1 inherited) | Field names do not prove data leakage. |
| API03_EXAMPLE_CREDENTIAL | SKIPPED (unchanged) | Raw example values deliberately unavailable. |
| API03_DESCRIPTION_SENSITIVE_EXAMPLE | SKIPPED (unchanged) | Raw descriptions deliberately unavailable. |
| API03_RESPONSE_SCHEMA_INCONSISTENT | SKIPPED (unchanged) | Insufficient comparability evidence. |
| API03_HTTP_SERVER | SUPPORTED (v1 inherited) | Does not prove the service accepts cleartext traffic. |
| API03_UNRESOLVED_SERVER | SUPPORTED (v1 inherited) | No DNS or network resolution attempted. |
| API03_DEPRECATED_OPERATION | SUPPORTED (v1 inherited) | Deprecated does not mean vulnerable. |
| API03_DEPRECATED_AUTH_SCHEME | SUPPORTED (v1 inherited) | Basic authentication is only a heuristic for legacy schemes. |
| API03_UNSUPPORTED_SECURITY_METADATA | SKIPPED (unchanged) | Unknown security metadata must be reported as coverage, not a finding. |

### New evaluator constraints
- `API03_AUTH_OVERRIDE_WEAKENS`: detects an explicitly empty override of a nonempty inherited security declaration; other ambiguous override relationships SKIPPED.
- `API03_AUTH_OAUTH_SCOPE`: only compares named OAuth scopes against locally declared scope keys, never OAuth credentials or runtime privileges.
- `API03_STRING_NO_BOUNDS`, `API03_ARRAY_NO_BOUNDS`: direct inline parameter schema keyword absence only; unresolved local parameter references SKIPPED.
- `API03_ADDITIONAL_PROPERTIES`: explicitly `true` on inline request-body schemas only; implicit defaults and references not assumed.
- `API03_ERROR_RESPONSE_GAPS`: compares declared 4xx/5xx/default response status keys; never concludes runtime error-handling failures.
- The seven unchanged unsupported rules remain unsupported deliberately: `AUTH_UNKNOWN_SCHEME` (ingestion rejects), `AUTH_INCONSISTENCY` (no safe related-policy equivalence), `OBJECT_PERMISSIVE` (broader object semantics unavailable), `EXAMPLE_CREDENTIAL` and `DESCRIPTION_SENSITIVE_EXAMPLE` (secrets/raw prose intentionally excluded), `RESPONSE_SCHEMA_INCONSISTENT` (no justified comparability), and `UNSUPPORTED_SECURITY_METADATA` (unknown input is coverage, not a finding).

### Additional isolated qualification (must be checked at final HEAD)
Real PostgreSQL tests exercise 8 simultaneous competing workers for one job, replay protection, cross-tenant rich RLS, queued cancellation, stale lease replacement, immutable report/snapshot access, forced transactional publication error with no partial evidence and successful fresh-run recovery. The Chromium Phase05 journey additionally launches v2 from the React UI, checks persisted v2 coverage and verifies zero customer network requests. No simulated Host integration is used.

## Immutable history / version compatibility
Migrations 007–008 are additive; 007 adds history/filter indexes, 008 adds the independent immutable rich metadata table; 001–006 are unchanged and old phase02-v1 normalized inventory plus inventory-v1 reports remain stored unchanged. Historical evidence is never regenerated. Comparison is scoped by tenant and target; incompatible engines, historical legacy correlation, mismatching coverage, and incomplete runs return non-comparable. A missing finding is only **no longer observed**, not VERIFIED_FIXED. Synthetic fixture comparisons stay fixture-only.

## Negative security boundaries
- Tenant identity is synthetic only and cannot be used in production.
- Full query results come from RLS-bound transactions; no unscoped find-by-ID exports.
- External URL contacts remain prohibited for importer, engine and worker.
- No Host approval, no real customer credentials, no production targeting, no mutation, no automatic remediation.
- Full report selection requires an existing completed assessment; incomplete work cannot export a completed result.
- Existing triggers keep reports, findings, evidence and rule results immutable; test any upgrade against populated earlier state.

## Current review gaps that cannot be hidden as HOST_BLOCKED
- Phase05 now supports additive new-import-only phase05-v2 metadata and an inventory-v2 engine. Seven originally unsupported families remain explicitly SKIPPED for the reasons above; they are not falsely counted as findings.
- The v5 versioned v1/v2 customer start contract is implemented; synthetic fixture start deliberately continues to require the preserved Phase04-specific attestation/profiles. That is an explicit capability boundary, not a substitute authorization.
- Phase05 adds real PostgreSQL competing-claim, stale lease, cancellation and injected-publication rollback tests. Their final-head results must still be independently checked; they do not establish unbounded reliability.
- Comprehensive Phase05 **final-head** hosted CI evidence must be provided separately before review. Prior Phase04 PASS does not count as Phase05 final-head PASS.
- Actual production Host integration remains independently HOST_BLOCKED and cannot be represented as an isolated completeness pass.

## Reproduction and qualification
`npm ci --no-audit --no-fund`; `npm run lint`; `npm run typecheck`; `npm test`; `npm run test:pg`; `npm run build`; `npm run test:browser`. All execution must be through **GitHub-hosted** Actions, with disposable PostgreSQL 16 service; never on founder laptop or self-hosted runner. Phase05 fast gates execute on intermediate commits; exactly one Full job executes at marker commit `[phase05-full]`.

## Strict verdict criteria
Phase05 can be labeled READY FOR INDEPENDENT REVIEW only after all 33 founder-defined gates PASS. Until remaining independently executable gaps are resolved and final-head CI succeeds, verdict **INCOMPLETE**. No partial implementation or test result authorizes ASSESSMENT_PRODUCTION_READY.
