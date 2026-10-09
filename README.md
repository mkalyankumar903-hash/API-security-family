# LumicSec — API Security Family

**Phase 0 isolated assessment development. NOT production-ready.**

This repository implements a genuinely rule-driven OpenAPI 3.1 / Swagger 2.0 SPEC_ONLY Assessment slice: React preview → Fastify API → independent PostgreSQL → queue worker → evidence-backed observations → deterministic report. All runtime API attack and live probe capability is disabled.

## Getting started (Windows PowerShell)

Requirements: Node.js 22+, npm 10+, Docker Desktop with Docker Compose.

```powershell
git clone https://github.com/mkalyankumar903-hash/API-security-family.git
cd API-security-family
git switch work/phase0-spec-only-assessment
Copy-Item .env.example .env
docker compose -f infrastructure/docker-compose.yml up -d
npm ci
npm run migrate
```

Launch three terminals in the same directory:

```powershell
npm run api
npm run worker
npm run dev
```

Open http://127.0.0.1:5173 and use the synthetic development token in .env.example **for local isolated testing only**. Register `https://api.fixture.invalid`, upload `fixtures/insecure.openapi.json`, and start SPEC_ONLY. The worker will write actual rules, evidence, findings and report to PostgreSQL. Upload `fixtures/secure.openapi.json` to prove that a secure declaration produces no rule findings.

Run repeatable verification:

```powershell
npm run typecheck
npm test
npm run test:pg
npm run build
```

The application connects as a dedicated **non-superuser** PostgreSQL role; an admin role only provisions the database at first initialization. Reusing a pre-role-separation Docker volume requires an intentional isolated test-volume reset. Never point these instructions at customer data.

Run scripts only against an isolated disposable PostgreSQL instance: test suites apply migrations, insert test tenant records and depend on the isolated synthetic authority.

## Safety and integration

Local auth is a static test-token→tenant map, explicitly guarded by `SYNTHETIC_AUTH_ENABLED=true`. The production server refuses to start without a real Host adapter; this phase does not implement that adapter and does not accept browser-supplied tenant IDs. No active API request is sent. The target URL is inventory metadata, not permission for scanning. The exact v0.3.1 candidate ZIP and v0.3.2 review/decision register were inspected and derived corrections are recorded; final Host resolution remains unavailable and the contract is NOT FROZEN.

The preview is not a global platform login. Main Platform owns identity, tenant, billing and canonical findings. Only Main Platform RetestVerificationAuthority can mark VERIFIED_FIXED. See `docs/PHASE0_LIMITATIONS.md`.

## Architecture

- `packages/contracts`: fail-closed request plan and permit-decision contract invariants
- `packages/assessment-engine`: safe parsing, operation normalization and deterministic rules
- `packages/database`: PostgreSQL transactions, enforced tenant RLS, queue and migrations
- `packages/service`: authorized versioned Fastify endpoints
- `packages/worker`: resumable, leased SPEC_ONLY processing and transactional finalization
- `packages/ui`: reusable React customer assessment UI
- `apps/standalone-preview`: local integration shell only
- `tests`: contract, unit, real-PostgreSQL and React integration tests
- `docs/api.openapi.yaml`: current implemented route contract

No production deployment, Phase 1 progression or penetration-testing functionality is authorized.

## Review remediation status
Offline OpenAPI structural validation, private worker queue principal, tested tenant denial, actual Playwright Chromium E2E, separate migration-admin credentials, read-only GitHub Actions and ESLint are included. Use npm run lint / typecheck / test / test:pg / build / test:browser. Browser tests start Fastify and Vite and use isolated PostgreSQL. Production remains disabled.

## Phase 1 — Secure API target onboarding (stacked draft PR)
API targets now have revisioned metadata, canonical HTTPS URL validation, lifecycle states, tenant-isolated scope proposals, challenge issuance/replacement/expiration/revocation, immutable audit history, test-only signed verification decisions and opaque credential references. Full React controls operate against Fastify and PostgreSQL. The historical Phase 0 assessment data and SPEC_ONLY offline pipeline are retained.
**No real Host verification, identity delegation, credential retrieval, DNS/HTTP scanning, network permits or production login is implemented.** Ownership states are PENDING_HOST_VERIFICATION or SYNTHETIC_VERIFIED_TEST_ONLY; never Host verified. Scope proposals are not Host approval.
Synthetic attestation issuer is disabled unless NODE_ENV is non-production and SYNTHETIC_VERIFICATION_ENABLED=true with an explicit **test-only** signing root. All authorized customer target network calls remain disabled.
To test on a disposable database, set NODE_ENV=test, SYNTHETIC_AUTH_ENABLED=true, SYNTHETIC_VERIFICATION_ENABLED=true, PHASE1_SYNTHETIC_SIGNING_KEY to a development-only value at least 32 bytes, and configure both PostgreSQL roles and the admin-only migration DSN. No production use of these values is authorized.
Run npm run typecheck, npm run lint, npm test, npm run test:pg, npm run build and npm run test:browser. The PostgreSQL tests include a separate actual populated Phase 0 upgrade database and preserve its historical target/spec. The Chromium suite exercises onboarding and Phase 0 assessment together.

## Phase 02 — API specification & offline discovery
The additive Phase 2 customer product supports specification-derived import of OpenAPI 3.0.x JSON/YAML, OpenAPI 3.1.x JSON/YAML, Swagger 2.0 JSON/YAML and bounded Postman Collection 2.1 JSON profiles. All imports run offline with no HTTP/DNS dereference, shell execution, pre-request scripts, customer endpoint crawling or active scanning.
The existing Phase0/1 assessment service, target lifecycle, workers, customer reports, signed synthetic tests and historical DB migrations are unchanged. Phase2 adds only forward migration 004_phase2_offline_discovery.sql, /v2 Fastify routes, a dedicated React explorer, immutable inventory snapshots and structural diff history. Each import version is bound to an existing tenant-owned target and the original Phase0 api_specifications and api_operations authority. Raw/source vs normalized fingerprint, immutable source pointer, status transition events, version number and eligibility are distinguished explicitly.
**Eligibility:** Legacy deterministic SPEC_ONLY assessment is supported only for already-qualified OpenAPI 3.1.x and Swagger 2.0. OpenAPI 3.0.x and Postman v2.1 are importable, explorable and comparable but deliberately **NOT eligible** for old Phase0 rules because coercion could alter evidence provenance. Attempts to assess them fail closed with HTTP 409. This is an explicit limitation, not a production-ready OpenAPI 3.0/Postman analysis claim.
**Safety:** Specifications describe declared, not runtime-discovered endpoints; metadata server URLs never become target permissions; source parsing never fetches remote refs; Postman auth values and scripts are not executed. The imported Postman stored source is redacted; raw SHA-256 remains based on original upload. No Host tokens/permits/network scans are enabled. Failed imports store safe diagnostic codes without authoritative inventory. Historical assessments remain bound to immutable spec IDs, report projections and evidence.
**Limitations:** Postman auth, variables, examples and raw bodies are inventory-only, no vault secrets or environment expansion. Collections may have unsupported features flagged in coverage warnings. Structural diffs are possible breaking-change candidates requiring review, not verified runtime compatibility. Enforced size/depth/ref/node/operation/folder limits and bounded V8 worker-thread heap (128 MiB old generation), import concurrency (4) and a 5 second worker deadline are implemented and positive/negative worker tests pass. A production network namespace and adversarial deadline kill under exhausted CPU are NOT VERIFIED. Main Platform contract still NOT FROZEN. No Host JWT/JWKS, delegated ownership, egress, permits, billing, signed events, canonical asset authority, production upload scanning or verified-fixed authority is present.
Run with a new disposable PostgreSQL 16 on isolated port; provision roles from infrastructure/postgres-init/001_roles.sql. Set DATABASE_URL, WORKER_DATABASE_URL, MIGRATION_DATABASE_URL, test-only SYNTHETIC_AUTH_ENABLED=true, non-production SYNTHETIC_VERIFICATION_ENABLED=true and test-only signing root. For local browser, also set VITE_DEV_TOKEN, VITE_API_BASE. Use npm ci && npm run typecheck && npm run lint && npm test && npm run test:pg && npm run build && npx playwright install chromium && npm run test:browser.
