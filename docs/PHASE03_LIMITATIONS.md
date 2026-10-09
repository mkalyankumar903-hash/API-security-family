# Phase 03 — Offline Deterministic API Assessment

Phase 03 uses the persisted immutable Phase 02 inventory with explicit engine selection inventory-v1. The original legacy-v1 assessment engine is preserved.

SPEC_ONLY: maxRequests = 0; methods = []. No live target scanning, Postman script execution, credential access, network egress, or Host permit generation.

UNKNOWN != SAFE. NO EVIDENCE != SAFE. FIX APPLIED != VERIFIED_FIXED.

## Security evidence policy

Catalog comprises 28 versioned rules. Unsupported and inapplicable checks are SKIPPED, with reasons in coverage rather than fabricated security findings. Every qualified observation has a stable SHA-256 occurrence fingerprint, cross-version correlation key, rule ID/revision, source pointer, non-secret evidence, impact candidate, confidence and review-required validation.

Raw examples and hidden schema attributes are not inferred. OpenAPI 3.0/3.1, Swagger 2.0 and Postman declarations do not have identical meaning.

## Routes

GET /v3/detection/engines
GET /v3/detection/capabilities
GET /v3/detection/rules
GET /v3/detection/rules/:ruleId
POST /v3/targets/:id/assessments
GET /v3/targets/:id/assessments
GET /v3/assessments/:id
GET /v3/assessments/:id/findings
GET /v3/assessments/:id/findings/:findingId
GET /v3/assessments/:id/coverage
GET /v3/assessments/:id/report
POST /v3/targets/:id/assessments/compare
POST /v3/assessments/:id/cancel

All routes use Phase 0–2 synthetic identity boundary with tenant-scoped database sessions. Creation requires idempotency key plus specificationId, mode SPEC_ONLY and engineVersion inventory-v1.

## Limitations

Missing maxLength, maxItems, additionalProperties, OAuth declared scope keys, raw examples and response-status-only details from Phase 02 normalization prevent reliable detection of those rule families. Absence of an observation does not prove the API safe or that a runtime issue is fixed.

Main Platform final identity, commercial authorization, trusted permits, controlled egress, canonical findings and retest authority are NOT FROZEN.

## Reproduction

.github/workflows/phase03.yml executes npm ci, npm run lint, npm run typecheck, npm test, npm run test:pg, npm run build and npm run test:browser on GitHub-hosted Ubuntu with disposable PostgreSQL and real Chromium.
