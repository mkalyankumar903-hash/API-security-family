# Engineering boundaries

Operate only within this independent API-security-family repository. Do not mutate Web Family or Main Platform.
No automatic progression beyond Phase 0. No claims of Host authority without deployed verified Main Platform integration.
Do not add any outbound request primitive to SPEC_ONLY engine or worker.
Keep tenant SQL inside withTenant transactions; RLS is mandatory.
No generated findings unless sourced from actual persisted specifications; never classify as confirmed runtime vulnerabilities.
Do not weaken or remove runtime-disabled mutation controls.
Do not make synthetic authentication available in production; it must fail closed.
Require PostgreSQL E2E, security negatives, typecheck, UI tests, and CI evidence before requesting phase review.
