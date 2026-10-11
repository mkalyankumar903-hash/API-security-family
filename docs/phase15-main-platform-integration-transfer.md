# API Family → Main Platform: reproducible complete source transfer, not a deployment

**Authoritative source:** `mkalyankumar903-hash/API-security-family` Phase15 Draft PR #16.
**Read-only integration destination:** `kalyankumarmalli480-sys/lumicsec-security-platform` (Main Platform **and** Web Family).
Legacy `securemsme-ai` is historical only. No Main Platform changes are performed.

## Build, verify, and securely stage source

The existing private Phase15 CI Full job uses a GitHub-hosted checkout, Node22, and:
```sh
node scripts/phase15-main-platform-source-transfer.mjs
node scripts/phase15-main-platform-source-transfer.mjs --verify
```
The private Actions artifact `phase15-main-platform-source-<exact-SHA>` contains
`api-family-source.tar.gz`, `source-inventory.json`, and `SHA256SUMS`.
This **SOURCE** archive is not the nine-file private compiled release candidate.
`source-inventory.json` enumerates every transferred tracked file, exact original
and proposed destination paths, byte size, SHA256, kind, environment variable **names**
(without values), 19 migration paths, source SHA and required denials.
The verification test extracts TAR into a throwaway location and checks every
file's hash/size against live tracked Git bytes and the complete archive member set.
CI/dev-only infrastructure role-bootstrap SQL and `.env*` are **excluded**.
Other source tests contain synthetic CI-only fixtures; never publish the source TAR as
a deployable asset or customer download. No live secrets/customer data are included
intentionally; review artifact permissions separately before approved transfer.

Proposed **non-executable staging** root in destination:
`integrations/api-family/source/<original API repo path>`.
The destination owner must inspect for collisions and review before even staging.
Do not blindly copy into `src/app`, `supabase/migrations`, `public/`, or Main
`package-lock.json`. No automatic cross-repository mutation occurs.
The existing compiled private RC supplies ready-to-install SDK/UI/service/worker
under separately verified checksums, without copying the API repository wholesale
into a running Next.js application.

## Exact mapping of modules

| API-owned source | Staged transfer relative path | Intended consumption |
|---|---|---|
| `packages/service/src/**` | `integrations/api-family/source/packages/service/src/**` | compiled Fastify 5 sidecar / guarded Host gateway (not Next.js route) |
| `packages/worker/src/**` | `integrations/api-family/source/packages/worker/src/**` | independent lease-fenced worker; no browser worker |
| `packages/database/src/**` | `integrations/api-family/source/packages/database/src/**` | PostgreSQL16 RLS connections / isolated migration authority |
| `packages/database/migrations/001–019` | `integrations/api-family/source/packages/database/migrations/**` | byte-identical SQL, **NOT** Main Supabase migrations |
| `packages/assessment-engine,pt,discovery,targets/**` | same paths beneath staging root | all actual assessment, discovery, governed PT and target engines |
| `packages/contracts/**` | same | provisional Host contracts, canonical V13, v0.3.2 unapproved |
| `packages/sdk/**` | same | private typed `V13Client`, caller auth and validated read-only responses |
| `packages/ui/**` | same | private `Phase15Mount`, tenant/session reset and no stale projection |
| `apps/**` | same | standalone preview only, not live Main UI |
| `tests/**`, `fixtures/**`, `scripts/**`, `.github/workflows/**` | same | actual historical tests, fixtures and build/CI replay |
| `package*.json`, `tsconfig*`, `vite*`, `Dockerfile.phase15`, `docs/**` | same | original dependency, runtime, reproducibility and docs |

Each file's source/destination is explicitly recorded in the machine-readable inventory.

## Verified compatibility at observed Main Platform Phase20 source HEAD

| Concern | API Family RC | Main Platform + Web Family | Status |
|---|---|---|---|
| Node | 22 | Next15 build tool / Node runtime not production qualified for API | Separate Node22 service readiness; HOST_BLOCKED |
| React/React DOM | 19.1.1 / 19.1.1, UI peers `^19.1.0` | 19.1.9 / 19.1.9 | semver compatible, actual Next mount NOT VERIFIED |
| Frontend | Vite React mount | Next.js 15.5.27 + Supabase SSR 0.6.1 | adapter/auth design required |
| Backend | Fastify 5.12.5 + private Node worker | Next.js route handlers / Web workers | separate runtime/infrastructure required |
| Database | PostgreSQL16, `pg` 8.16.3 | Supabase Postgres/PostgREST/Auth, existing `public` schema | NEVER blindly merge/replay |
| Packages | private API SDK/UI 0.15.0-rc.1 | Main lockfile is independent | isolated install then owner-controlled peer review |
| Host authority | `api-family-host-adapter-v15-draft` CI simulator only | Supabase `auth.getUser` and Web-only scope enforcement | production JWT/JWKS delegation NOT IMPLEMENTED |

## Database safety — authoritative decision gate

All **19 canonical API migrations** are immutable and preserved. They assume
`public.api_*` SQL tables, functions with `SECURITY DEFINER` using PostgreSQL
`public` namespace, separate `api_queue` schema and `api_family`, worker and QA roles.
RLS relies on transaction-scoped `api.tenant_id`; this is **not equivalent** to
Supabase Auth JWT claims or PostgREST roles. Main already contains Supabase-owned
`public` tables, functions, grants, policies, extensions, historical migrations,
`auth.users` relationships and Web business objects.

**Required approach:** retain API in a **separate isolated PostgreSQL16 database**
with separate DB migration principal, app and worker identities as the initial
proposed P0-safe staging option; actual Host owners must approve database
lifecycle, credentials, backup, migration ordering and integration credentials.
Before considering same-DB/namespace migration: inspect a disposable clone of
the real Main schema, query object/extension/grant/function collisions, specify
forward-only namespaced migrations, audit `SECURITY DEFINER` and RLS grants,
evaluate migration ordering, rollback and irreversible transforms, run role-negative
tests and obtain explicit security signoff. No live Supabase access performed.
No direct SQL permission to `auth` schema or public API schema granted.

## Missing Level C contracts and executable gates

- **Identity/membership:** Main Supabase sessions, org/client membership and RBAC
  must translate to Host-issued, expiring, audience/tenant-bound API credentials
  with JWKS trust, key rotation/revocation. API simulator keys never become real Host keys.
- **Ownership/permits:** Main owner-controlled asset ownership, scoped target/method
  limits, explicit consent, signed leases, revocation and time-of-use revalidation;
  GET/HEAD/OPTIONS conflict remains NOT FROZEN.
- **Commercial:** API usage meters are `NON_BILLABLE_OBSERVATION`; any unified credits
  wallet, reservation/settlement, enterprise contracts require Main owner policy decisions.
- **Evidence/findings:** API immutable tenant-bound evidence and report metadata
  must map to Main canonical findings; only approved Main `RetestVerificationAuthority`
  can set `VERIFIED_FIXED` after authoritative retest (CI and fix applied never suffice).
- **Signed internal events:** Main owner must design trust/nonce/replay persistence,
  tenant binding and fail-closed restart recovery; CI HMAC simulator proves no Host approval.
- **UI/SDK:** private archives must be mounted through an approved Main Next client
  component, real session token flow, error/tenant switching tests, hosted E2E.
  No new Main route/mount was created in this preparation.

## Ready / Blocked / Not verified

| Requirement | Evidence | Status |
|---|---|---|
| Full API source + 19 migrations + tests/CI package | CI tar, inventory and SHA256 verifier | READY once current exact SHA Full CI passes |
| Independently installable compiled API service/worker/SDK/UI | Existing private Phase15 candidate and clean E2E | READY (isolated Level B) |
| API tenant/RLS and worker security | Existing Postgres16/RLS/worker Full regression | READY for independent isolated security review |
| Production API DB schema inside Main Supabase | public/api_queue/role assumptions conflict with hosted grants | BLOCKED pending approved namespace-safe plan |
| Real Main session/JWKS and tenant delegation | no production issuer/adapter authority | BLOCKED |
| Host-scoped permits, billing, internal events, canonical retest | unfrozen P0 contracts / no actual authorized Host adapter | BLOCKED |
| Actual Next15 + private React plugin hosted integration | No Main write or hosted Chromium qualification performed | NOT VERIFIED |
| Actual private-source transfer into Main repo | Explicitly prohibited in this task; package only | NOT VERIFIED |
| Production deployment, real target execution | no authorization | BLOCKED |

**Security boundaries:** No production Supabase data access, Main repository write, merge,
deployment, live scanning, package registry publication, real payment authorizations,
external event delivery, or canonical VERIFIED_FIXED promotion. Phase14 known LOW
repeated-revocation diagnostic remains open; Phase15 MEDIUM credential-leakage
findings remain covered by independent execution gates.
