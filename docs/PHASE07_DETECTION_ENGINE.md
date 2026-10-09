# Phase 07 — deterministic synthetic API penetration testing (pt-detection-v1)

## Security and trust boundary

**ISOLATED SYNTHETIC API PENETRATION TESTING — NOT CUSTOMER PRODUCTION VULNERABILITY VERIFICATION.**

Phase07 only evaluates trusted, repository-owned `pt-security-v1` in-process Fastify fixture operations. The test authority is disabled in production. No real customer target hostname, DNS, redirect, remote URL, session cookie, real credentials, or real customer API is read or contacted. Real Host authorization and canonical vulnerability promotion remain **BLOCKED**.

The authorized data path is React → authenticated Fastify tenant → PostgreSQL FORCE RLS → existing private queue → Phase06 governor → in-process fixture → redacted evidence → deterministic rules → atomic immutable PT report. A customer can request synthetic authorization but cannot issue, sign, or revoke test permits.

V7 permit envelopes use `pt7v1` (HMAC-SHA256) and are exclusively bound to `pt-security-v1`. Phase06 permits remain `pt6v1` bound to `billing-safe-v1`. PostgreSQL stores the original *unsigned* canonical payload, public claims and SHA256 fingerprint, never the signed bearer or MAC. The worker re-derives and checks the signed test authority credentials at every boundary. The synthetic permit must never be treated as a real Host permit.

## Trusted fixture policies (version 1)

- `/pt/account`: valid alice, bob, admin → 200; anonymous, invalid, expired, revoked → 401 unless the explicitly vulnerable `MISSING_AUTH_ENFORCEMENT` profile is selected.
- `/pt/resources/bob`: bob or admin → 200; alice → 403; vulnerable `CROSS_USER_ACCESS_WEAKNESS` allows alice → 200.
- `/pt/admin`: admin → 200; alice → 403; vulnerable `ROLE_RESTRICTION_WEAKNESS` allows alice → 200.
- `/pt/confidential`: alice → 200; secure profile response contains no forbidden `$.internalAccessToken` field and uses `Cache-Control: private, no-store`; separate vulnerable profiles introduce exactly one negative behavior.
- All fixture interactions are GET/HEAD-only, in-process, body cap 2048 bytes, fixed identity and profile enums, no user code, no external network APIs.

## Implemented executable rule catalog

| Stable rule ID | Revision | Positive trusted fixture profile | Secure negative policy | Evaluations | Impact |
|---|---|---|---|---:|---|
| PT-AUTH-ANONYMOUS | 1.0.0 | MISSING_AUTH_ENFORCEMENT | Anonymous denied, valid alice allowed | 2 | MEDIUM |
| PT-AUTH-INVALID | 1.0.0 | MISSING_AUTH_ENFORCEMENT | Invalid identity denied, valid alice allowed | 2 | MEDIUM |
| PT-AUTH-EXPIRED | 1.0.0 | MISSING_AUTH_ENFORCEMENT | Expired identity denied, valid alice allowed | 2 | MEDIUM |
| PT-AUTH-REVOKED | 1.0.0 | MISSING_AUTH_ENFORCEMENT | Revoked identity denied, valid alice allowed | 2 | MEDIUM |
| PT-BOLA-CROSS-USER | 1.0.0 | CROSS_USER_ACCESS_WEAKNESS | Bob owns resource, alice denied | 2 | HIGH |
| PT-FUNCTION-ROLE | 1.0.0 | ROLE_RESTRICTION_WEAKNESS | Admin allowed, alice denied | 2 | MEDIUM |
| PT-SENSITIVE-FIELD | 1.0.0 | SENSITIVE_RESPONSE_EXPOSURE | Forbidden field path absent | 1 | MEDIUM |
| PT-CONFIDENTIAL-CACHE | 1.0.0 | INSECURE_CACHE_POLICY | Private no-store policy present | 1 | LOW |

Each supported rule compares actual trusted response metadata against the repository-owned policy oracle; a passing secure control is necessary for comparative authorization detections. Missing, mismatched, or invalid evidence produces INCONCLUSIVE, not an invented vulnerability. Results are `PASS`, `OBSERVED`, `SKIPPED`, or `INCONCLUSIVE`. No CVSS is assigned; confidence for observed synthetic policy breaches is HIGH **only within the trusted synthetic fixture**.

No result claims a real customer vulnerability. Rule limitations: no mutation, no POST/PUT/PATCH/DELETE, no credential recovery, no user-defined scripts, no external API security verification, no real BOLA confirmation, no production reliability or exploitation testing. A synthetic observed BOLA-like behavior does not prove a customer's production BOLA. Absence of an observation is not VERIFIED_FIXED.

## Detection admission, governor, and evidence

An authenticated synthetic tenant chooses an imported inventory and applicable fixture operations, proposes immutable Phase06 PT scope with v7 fixture identity, requests authorization, and waits for the separate test issuer. Detection admission checks signed token, target, scope, specification, fixture, operation lists, tenant, revision, method, exclusions, life cycle, idempotency, remaining permit evaluation count, per-minute rate and concurrency, and emergency stop. The immutable detection plan stores selected rule IDs/revisions, fixture profile/version, synthetic identity cases, approved operation IDs and SHA256 fingerprint.

For **every fixture interaction** the existing Phase06 governor validates current test-key HMAC and permit binding with the private worker's claimed queue lease and target+stop+permit row locks. It reserves exactly one permit evaluation, executes in-process with transaction-guarded boundaries, and settles CONSUMED/UNCERTAIN conservatively. A RESERVED evaluation left after a crash is marked UNCERTAIN on replay, never re-executed. Revocation/cancellation/stop serialize at the next operation boundary: this does **not** guarantee mid-instruction preemption. Report publication repeats authorization and stop/lease checks and is atomic: a failed/denied/cancelled job does not publish a misleading success report.

The redaction collector persists only method/path/actor label/status, approved field paths, response-byte count, cache directive, SHA256 hash of safe public metadata, fixture profile/version; no raw authorization header, bearer, API key, sensitive placeholder value or arbitrary full body. Fingerprints are stable across compatible identical fixture executions; job IDs/timestamps differ. Findings must retain `SYNTHETIC_PT_OBSERVATION` and `runtimeCustomerVerification=false` semantics.

Migration 011 adds tenant-bound immutable plan/results/reports, ledgered evaluation references with safe state transitions and FORCE RLS; retains migrations 001–010. `api_family` is a tenant RLS application principal; `api_family_queue` is a distinct private worker principal. No privileges are granted for arbitrary fixture execution or customer egress. History comparisons require same target, specification fingerprint, fixture version and rules/revisions; `newlyObserved`, `stillObserved`, `evidenceChanged`, and `noLongerObserved` are synthetic comparisons only.

## API and React scope

- GET `/v7/pt/rules`, GET `/v7/pt/fixtures`
- POST `/v7/pt/scopes/:id/detections` (test-only signed permit required, Idempotency-Key)
- GET `/v7/pt/jobs/:id`, `/v7/pt/jobs/:id/evaluations`, `/v7/pt/jobs/:id/findings`, `/v7/pt/jobs/:id/coverage`, `/v7/pt/jobs/:id/report`, `/v7/pt/jobs/:id/export`
- GET `/v7/pt/targets/:id/history`, `/v7/pt/jobs/:id/compare/:otherId`
- Reuse Phase06 `/v6/pt/jobs/:id/cancel`, `/v6/pt/scopes/:id/request-authorization`, and isolated separate `/v6/pt/test-authority` endpoints.

React `PtDetectionConsole` is integrated into accepted Phase06 PT console; it selects imported spec, fixture profile, trusted rules, scope/permit and budget; views worker job/report, redacted fixture evidence, coverage, history, comparisons and JSON export.

## Deterministic qualification scenarios and asynchronous admission recovery

The Chromium journey MUST await the exact scope-bound `POST /v7/pt/scopes/:id/detections` HTTP response before invoking the in-process private worker test harness. A React button click alone only schedules asynchronous work; it does not prove HTTP admission, a database commit, or queue insertion. The browser test now asserts HTTP 201, returned job ID, matching persisted `scope_id`, and persisted `QUEUED` status before processing. This avoids a false-zero queue drain without bypassing admission controls or adding timing sleeps.

The regression suite is structured to verify the following independently rather than relying on a catalog count:

- Every rule: vulnerable trusted fixture positive, secure fixture negative, missing evidence INCONCLUSIVE, deterministic fingerprint, approved redacted evidence, fixed fixture-only semantics.
- Every rule through real PostgreSQL worker: new separately authorized scope, private queue claim, actual governed fixture evaluation ledger, exactly one expected synthetic observation, zero customer network requests and no raw sensitive placeholder value.
- Parallel same-key admission: real competing PostgreSQL transactions resolve to one immutable job, one queue row, one governed execution. Different-key concurrent admission within the same permit must obey max concurrency.
- Permit absence/revocation, cancellation and emergency stop: no unauthorized fixture interaction, no completed report, no revival of a revoked permit after resume.
- Chromium customer journey: genuine React/Fastify/PostgreSQL/worker positive and secure negative; permit denial, redacted receipt/report, history/comparison without VERIFIED_FIXED, customer UI cancellation, signed-authority stop, forbidden synthetic POST scope and no customer-host network request.
- The existing Phase00–06 suites remain part of comprehensive qualification. Missing/failing/skipped CI is never interpreted as a passed assessment.

Test-only `PT_TEST_AUTHORITY_ENABLED` and signing keys exist exclusively in the isolated CI environment. These tests cannot authorize customer scanning, production exploitation or Host findings.

## Populated upgrade, worker claim fencing and conservative no-replay

`tests/phase07-upgrade.pg.test.ts` constructs a separate populated Phase06 migration-010 PostgreSQL database including a previously issued real HMAC-bound test-only permit, historical inventory, evidence and immutable reports. It applies additive migration 011 transactionally and verifies preservation of prior rows, permit validation without a persisted bearer, the new four FORCE RLS tables, separated app/worker privileges, and the new engine-version constraint. This is separate from the fresh 001–011 migration qualification.

`tests/phase07.pg.test.ts` exercises all eight detector rules end-to-end through actual private PostgreSQL queue claims and the governor; competing same-key admission is exactly-once and distinct-key permit admission respects concurrency limits. It additionally verifies that a replaced worker claim cannot settle reservations owned by a later claimant, and that a terminal cancellation which deletes the queue record may settle stranded evaluation budget only as `UNCERTAIN`, never replay or mark the assessment completed. A missing queue row on an active assessment does not grant settlement authority.

The target registration and both scope proposals in the Chromium test wait for exact committed HTTP responses; the browser never infers a successful scope from a click or an arbitrary sleep. The secure and vulnerable comparison journeys verify separate permit/scope binding and persistence before queue processing.

## Accepted Phase06 customer UI compatibility

The existing Phase06 authorization and safe execution region retains its accessible `API Penetration Testing` heading. The nested Phase07 detection console uses a distinct heading, avoiding duplicate locator matches and ambiguity for assistive technologies. `tests/browser/phase7.spec.ts` verifies the original heading remains uniquely addressable. Targeted Chromium qualification executes **both** accepted `phase6.spec.ts` and new `phase7.spec.ts` as separate Playwright processes so old and new customer flows are tested without shared database-pool teardown conflicts.

## GitHub-hosted qualification (required, not assumed)

Workflow `.github/workflows/phase07.yml` on `work/phase07-api-pt-detection-engine`:

- Fast: `npm ci --no-audit --no-fund`; `npm run lint`; `npm run typecheck`; `npm test`
- Targeted PG marker `[phase07-pg]`: actual PostgreSQL 16 via service, migrations and `npm run test:pg`.
- Targeted browser marker `[phase07-e2e]`: PostgreSQL 16 and real Playwright Chromium.
- Final marker `[phase07-full]`: frozen install, ESLint, strict TS, all unit/contract/security regressions, real PostgreSQL migrations/upgrades/races, production React build and actual Chromium E2E.
- Verify **actual** `full` job ran and final branch HEAD = Draft PR head SHA = qualifying Full CI head SHA. Do not treat skipped Full CI as successful acceptance.

### Inherited Host blockers

Real Host JWT/JWKS; organization/member delegation; production target ownership proof and revision authority; credential vault; real Host signed permits; controlled network egress/SSRF defense; commercial entitlements; canonical finding authority; RetestVerificationAuthority; finalized plugin contract. All remain BLOCKED for production. `UNKNOWN ≠ SAFE`; `NO EVIDENCE ≠ SAFE`; `FIX APPLIED ≠ VERIFIED_FIXED`; `CI PASS ≠ VERIFIED_FIXED`.
