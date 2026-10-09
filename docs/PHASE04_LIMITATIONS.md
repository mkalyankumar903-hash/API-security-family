# Phase 04 — Isolated Authenticated API Fixture Evaluation

STATUS: synthetic-fixture-only; not a customer runtime pentest.

## Security and authority boundary
- No customer base URL is ever an execution destination. No HTTP sockets, external fetch, DNS resolution, shell, external Postman scripts, untrusted fixture code or user-defined fixture routes.
- Auth evaluation uses only fixed, versioned Fastify.inject in-process routes.
- SPEC_ONLY remains maxRequests=0, methods=[], with internal fixture interactions counted separately.
- Production NODE_ENV fails closed; an explicit SYNTHETIC_AUTH_ENABLED=true opt-in is required.
- Phase01 credref references are labels and never authorization to retrieve real credentials. All generated fixture credential material is ephemeral and redacted from reports/logs.
- User input cannot assign arbitrary trusted role, fixture policy or execution host.
- The deliberate synthetic fixture cross-user defect is NOT proof of customer BOLA or any customer security flaw.
- UNKNOWN != SAFE. NO EVIDENCE != SAFE. FIX APPLIED != VERIFIED_FIXED.

## Supported synthetic auth
Bearer, header API key, HTTP Basic, OAuth2-style renewable/expiring test token, cookie/session, anonymous baseline, invalid/missing credentials, expiry, revocation, wrong issuer, wrong audience, tampering, profile rotation, logout, role constraints and resource ownership.

## Workflow
1. Register SYNTHETIC target and import immutable v2 specification.
2. Add Phase01 opaque credential reference; do not enter a secret.
3. Create a trusted fixture profile and select a source-controlled fixture and identity key.
4. Validate credential-reference presence, active synthetic target, unchanged target/scope revision, profile and imported spec.
5. Admit auth-fixture-v1 assessment in SPEC_ONLY using existing private queue.
6. Worker evaluates source-controlled authorization policy with in-process Fastify.inject, capturing safe status/metadata only.
7. Persist evaluation evidence/finding/report transactionally with tenant RLS and immutable history; display redacted report and deterministic historical comparison in React.
8. Cancel or revoke through dedicated endpoints; revalidate modified profile versions.

## API inventory
- GET /v4/auth/capabilities and GET /v4/auth/fixtures
- GET, POST /v4/targets/:id/profiles
- PATCH /v4/profiles/:id
- POST /v4/profiles/:id/validate and POST /v4/profiles/:id/revoke
- GET /v4/profiles/:id/history
- GET, POST /v4/targets/:id/assessments
- GET /v4/assessments/:id
- GET /v4/assessments/:id/evaluations
- GET /v4/assessments/:id/findings
- GET /v4/assessments/:id/evidence/:evidenceId
- GET /v4/assessments/:id/report and GET /v4/assessments/:id/coverage
- POST /v4/assessments/:id/cancel
- POST /v4/targets/:id/assessments/compare

## Deferred Main Platform integration
Real Host JWT/JWKS, current membership and delegation, target ownership, credential vault authorization, customer network permits, trusted egress, commercial authorization, canonical finding promotion, RetestVerificationAuthority and Host plugin contract freeze remain BLOCKED.

## CI
Fast GitHub-hosted checks run on ordinary Phase04 development commits. Exactly one comprehensive GitHub-hosted PostgreSQL 16 + Chromium + Phase00–04 regression run must execute at the exact final commit explicitly marked [phase04-full]. Any changes after that commit invalidate qualification. Draft PR must remain unmerged.
