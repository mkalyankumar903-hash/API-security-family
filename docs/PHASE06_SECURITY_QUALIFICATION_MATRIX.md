# Phase 06 security qualification — 20-area evidence matrix (rework)

This is a **source-reconstructed 20-area review matrix** from Phase 06's API/PT contracts, threat model, historical tests and security-qualification request. The text of the **original Master Prompt's 20 numbered areas is not available in this checkout**; therefore, no claim of verbatim one-to-one identity is made. Areas below distinguish multi-session concurrency from static, isolation, migration and runtime checks. Outcomes require final-head Actions evidence; a test's existence is not a PASS without a successful run.

| # | Area (nature) | Executable evidence | Limits |
|---|---|---|---|
| 01 | Forward-only migrations 001–009 + additive hardening 010 (schema) | phase2.pg, phase06.pg, phase06-upgrade.pg | Preserve historical migration009; verify populated Phase05 data |
| 02 | FORCE RLS and worker/app DB role isolation (privileges) | phase06.pg, phase06-races.pg | DB owner/superuser/backup administrators remain privileged |
| 03 | Customer scope validation, strict target/spec/GET-HEAD limitations (contract) | phase06.pg, phase06-contract.test | No real customer authorization |
| 04 | Explicit authorization request separated from issuer (control-plane) | phase06.pg | Test issuer only |
| 05 | Signed permit HMAC, canonical serialization, tampering resistance (crypto) | phase06-contract.test | Isolated ephemeral test key, never Host/KMS |
| 06 | Permit fingerprint binding / non-bearer persistence (crypto + DB) | phase06-contract.test, phase06.pg | 010 drops signed_token; earlier DB backups may retain old synthetic values |
| 07 | Issuer/audience/tenant/target/spec/revision/expiry enforcement (policy) | phase06-contract.test, phase06.pg | Production blocked |
| 08 | Fixed in-memory GET/HEAD fixture, zero customer-network requests (execution) | phase06-contract.test, phase06.pg, browser/phase6.spec.ts | No real HTTP transport |
| 09 | Simultaneous issuance idempotency, only one permit/scope (race) | phase06-races.pg | Separate concurrent clients |
| 10 | Simultaneous equal-key job admission idempotency (race) | phase06-races.pg | Transactionally serialized via tenant stop lock |
| 11 | Cross-tenant reads/receipts/reports isolation (security) | phase06-races.pg, phase06.pg | SQL RLS + API response tests |
| 12 | Multiworker permit budget; no double consumption (race) | phase06-races.pg | Counters and ledger checked |
| 13 | Simultaneous rate-window consumption/exhaustion (race) | phase06-security-qualification.pg | Real permit-row blocker observed via pg_blocking_pids |
| 14 | Concurrent execution/job slots, cap and release (race) | phase06.pg, phase06-security-qualification.pg | Applies to queued/processing PT jobs |
| 15 | Revocation vs pre-evaluation worker admission (race) | phase06-security-qualification.pg | Committed revocation precedes worker boundary |
| 16 | Revocation after RESERVED, before actual fixture call (race) | phase06-security-qualification.pg | Real authority endpoint; operation-boundary check |
| 17 | Cancellation after RESERVED, before actual fixture call (race) | phase06-security-qualification.pg | Real cancel endpoint; UNCERTAIN conservative settlement |
| 18 | Emergency stop vs final report publication (race) | phase06-security-qualification.pg, phase06-races.pg | No retroactive/preemptive interruption of already-run in-memory fixture |
| 19 | Multiworker lease recovery, no replay/duplicate receipt (race) | phase06-races.pg, phase06-security-qualification.pg | Claim token/ledger state; stale lease recovery |
| 20 | Report rollback, immutable audit, FAILED/CANCELLED vs success (failure injection) | phase06-races.pg, phase06.pg, phase06-security-qualification.pg | Receipt-fault injection and stop/cancel state checks |

## Permit storage hardening

Migration **009 remains untouched**; the forward-only **010** replaces the permit guard function and removes `api_pt_permits.signed_token` from already migrated tables. Synthetic permit issuance still performs HMAC-SHA256 and original signed-token verification in ephemeral memory, then persists **non-secret claims JSONB and SHA-256 token fingerprint only**. Worker and service reconstruct versioned field order (PostgreSQL JSONB order is not the issuer's JSON order), re-derive HMAC inside the isolated test process, compare the whole canonical token's digest in constant time and then apply the original time, audience, tenant, revision, authorization and budget enforcement. A claims/hash database disclosure alone cannot recover the HMAC. The full bearer is never inserted after hardening.

Database table access is available to tenant-scoped `api_family` and `api_family_queue` roles under FORCE RLS, and privileged database administrators/owners and backup operators. Customer endpoints select only scoped permit metadata and never serialize signed test bearer contents. The worker requires the ephemeral `PT_TEST_SIGNING_KEY` to revalidate. Signing-key compromise, malicious application runtime, past backups with original bearer values, and unauthorized DB-owner actions remain threats. Old signing keys intentionally become invalid across key rotations. No fake encryption, hardcoded cryptography, or production authority is introduced.

## Transaction boundaries and settlement

Locks guard stop, target, permit, job, lease, and ledger around admission/execution/final publication. Actual independent PostgreSQL transactions coordinate through explicit test barriers and/or observed blocking PIDs. Cancellation, stop or lease loss after a durable reservation conservatively settles it as UNCERTAIN, consumes rather than refunds capacity, and cannot publish a successful report. Stop/revoke apply at subsequent guarded operation boundaries; Phase 06 does **not** promise preemptive interruption of a synchronous operation already executing. No customer API requests or vulnerability finding promotion occur.

## Still blocked

Main Platform Host JWT/JWKS delegated permissions; target ownership/authorized environment; real production issuance/revocation and signing authority; outbound egress SSRF/redirect controls; credential vault; entitlements; canonical findings; and exclusive RetestVerificationAuthority. This isolated synthetic slice is **not production-ready**. UNKNOWN != SAFE. NO EVIDENCE != SAFE. CI PASS != VERIFIED_FIXED.

## CI proof standard

Only a successful Full CI at the **exact branch/PR HEAD**, including PostgreSQL security races, fresh/upgrade 001–010, unit/contract tests, ESLint, TypeScript, build and Chromium, can qualify the isolated rework. Prior-head successes do not count. Reviewers must read executed logs and note any remaining gaps, rather than assuming that the 20 table rows represent 20 distinct race tests.
