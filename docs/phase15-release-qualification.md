# Phase 15 — evidence register (live engineering work)

Current status: **TARGETED REWORK REQUIRED / NOT YET VERIFIED.** This file does not claim Phase 15 acceptance from the original prompt or CI runs on older SHAs.

## Exact predecessor evidence

- Accepted Phase14 anchor: `418f07bd8efed24d6094b84ac71aacfac0097e54`.
- Predecessor Draft PR #15 remains unmerged. Authoritative independent Phase14 Full CI: run 38119972126, job 114412698270, 65/65 successful steps, 418 tests.
- Migrations 001–019 remain source-preserved. There is no cosmetic migration 020.
- Nonblocking **LOW** risk: repeated idempotent permit-revocation diagnostic can look like another transition; not silently claimed fixed.

## Requirement-level implementation matrix (must be updated with exact final-HEAD CI)

| ID | Scope and file | Artifact / contract | Test / CI | Status | Limitation / owner |
|---|---|---|---|---|---|
| P15-A | Exact-state Phase14 baseline | Source SHA above | GitHub PR/CI readback | IMPLEMENTED_AND_VERIFIED | Existing isolated baseline only |
| P15-B | Private binary candidate builder `scripts/phase15-build.mjs` | api-service, api-worker, SDK, UI, migration, provisional contracts | `phase15:build` | NOT_YET_VERIFIED | Actual GitHub clean compile required / API Family |
| P15-C | SHA-256 and archive paths `scripts/phase15-verify.mjs` | manifest + SHA256SUMS | `phase15:verify` | NOT_YET_VERIFIED | Independent artifact integrity pending / API Family |
| P15-D | Clean production dependency install `scripts/phase15-clean-install.mjs` | Runtime, private SDK/UI archives | `phase15:install` | NOT_YET_VERIFIED | Need Node22 hosted proof / API Family |
| P15-E | CI-only signed envelope `packages/contracts/src/host-adapter-v15.ts` | provisional draft adapter v15 | `tests/phase15-host-contract.test.ts` | PARTIALLY_IMPLEMENTED | Does not establish Host issuer/JWKS/entitlement/ownership / joint |
| P15-F | React read-only mount `packages/ui/src/Phase15Mount.tsx` | private UI `0.15.0-rc.1` | package import | PARTIALLY_IMPLEMENTED | Chromium lifecycle, multi-tenant/session switches pending / API Family |
| P15-G | Fresh/repeated/concurrent packaged migrations `scripts/phase15-packaged-pg.sh` | SQL 001–019 + compiled runner | Full CI PostgreSQL16 | NOT_YET_VERIFIED | Interrupted/restore and populated upgrades remain historical source tests / API Family |
| P15-H | Worker service startup and Host denial | compiled JS archives | clean-install smoke | NOT_YET_VERIFIED | Actual integrated worker process with test PG needed / API Family |
| P15-I | Container non-root unpushed build | pending | pending | NOT_YET_VERIFIED | API Family |
| P15-J | Packaged offline import→worker→evidence→report→SDK/UI E2E | pending | pending | NOT_YET_VERIFIED | API Family |
| P15-K | Historical Phase00–14 full regression | `.github/workflows/phase15.yml` | `[phase15-full]` | NOT_YET_VERIFIED | Must pass at exact final HEAD / API Family |
| P15-L | Source-to-bundle traceability | machine-readable manifest | SHA256 sums | NOT_YET_VERIFIED | No public provenance signature / API Family |
| P15-M | Production identity, RBAC, billing, ownership, permits, findings, RetestVerificationAuthority | NO synthetic substitution | real Host qualification required | HOST_BLOCKED | Main Platform Host owner |
| P15-N | Actual hosted E2E and production operational approval | NONE | real Host qualification required | HOST_BLOCKED | Main Platform Host owner |

No `VERIFIED_FIXED` promotion or live scanning is authorized by any simulator assertion.

## Boundary and version policy

The v0.3.2 source matrix explicitly says `NOT FROZEN`. The independent API Family adapter string `api-family-host-adapter-v15-draft` is a draft test interface, **not a production contract freeze**. Missing Host authority must be reported as `HOST_AUTHORITY_NOT_CONFIGURED`; no fallback to simulation.

## Final exact-head acceptance checklist — pending

- Branch HEAD = Draft PR HEAD = authoritative Full run HEAD
- CI Full historical unit, actual PostgreSQL16, real Chromium and PDF, private SDK, releases and security negatives all successful
- No failed or skipped mandatory Full job steps
- Private release archive inventory and SHA-256 read back
- Clean install and independent runtime startup, worker shutdown/restart and 19 forward-only migrations proven
- Host simulator tests are isolated and production trust refuses test roots
- Final evidence comment, documentation, and named pending Host owners read back from GitHub
- Independent security reviewer accepts only *after* engineering qualification

**Do not advertise Level B engineering accepted until every independently executable requirement is verified.** 
