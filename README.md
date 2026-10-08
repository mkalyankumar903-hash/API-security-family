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

Run scripts only against an isolated disposable PostgreSQL instance: test suites apply migrations, insert test tenant records and depend on the isolated synthetic authority.

## Safety and integration

Local auth is a static test-token→tenant map, explicitly guarded by `SYNTHETIC_AUTH_ENABLED=true`. The production server refuses to start without a real Host adapter; this phase does not implement that adapter and does not accept browser-supplied tenant IDs. No active API request is sent. The target URL is inventory metadata, not permission for scanning. SCHEMA-01...04 validators are preliminary because original Main Platform v0.3.2 contract files are not available in this repository.

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
