# LumicSec API Security Family Phase 15 — Level B engineering qualification ledger

Candidate **0.15.0-rc.1**, accepted stacked predecessor `418f07bd8efed24d6094b84ac71aacfac0097e54`, existing Draft PR **#16**. This source document defines release acceptance conditions; **the exact-head Full CI and signed-off PR comment are the authoritative outcome**. The document itself does not prove an execution and never upgrades an unverified candidate.

## Immutable trust constraints

- All customer/prod Host authority remains `HOST_AUTHORITY_NOT_CONFIGURED`; CI simulator is **only** for GitHub Actions under `NODE_ENV=test` and deliberately unsupported elsewhere.
- No production identity/JWKS, permissions, asset ownership, permitted scanning, billing, canonical findings, `VERIFIED_FIXED`, deploy, registry publication or public endpoint.
- v0.3.2 source contract remains **NOT FROZEN**. Phase15 draft adapter cannot substitute approved Host contracts.
- Historical migrations **001–019** are unchanged, no migration 020. The source must preserve all Phase00–14 isolation and safety gates.
- Accepted Phase14 **LOW open risk**: repeated idempotent permit-revocation diagnostic can misleadingly resemble a fresh state transition. Not remediated and not waived.

## Requirement → source → installed artifact → mandatory GitHub Full gate

| ID | Independent Level B requirement | Source file(s) | Artifact(s) | Mandatory gate / proof |
|---|---|---|---|---|
| A01 | Compiled API/worker code, runtime-only locked dependencies, no `tsx` | `scripts/phase15-build.mjs`, `tsconfig.phase15.runtime.json`, dedicated network-denied `worker-entry-phase15.mjs` | `api-service.tar.gz`, `api-worker.tar.gz` | Build, clean install and production startup denial |
| A02 | SDK ESM & d.ts installed outside checkout | `packages/sdk` | `sdk-private.tgz` | SDK isolated ESM import, packaged E2E |
| A03 | Mount entrypoint, React peer imports, denied Host authority | `packages/ui/src/Phase15Mount.tsx` | `ui-private.tgz` | Clean UI install, actual .tgz Chromium mount and read-only state |
| A04 | Historical 001–019 SQL exact preservation | `packages/database/migrations` | `postgres16-migrations-001-019.tar.gz` | Packaged fresh, repeat and simultaneous invocations; historical populated preservation |
| A05 | Provisional API & upstream contracts NOT FROZEN | `packages/contracts`, OpenAPI docs | `contract-schemas-draft.tar.gz` | Contract/archive verification; incompatible versions deny |
| A06 | Source provenance, reproducible private bundles and forbidden-path scanning | `scripts/phase15-build.mjs`, `scripts/phase15-verify.mjs` | `manifest.json`, `SHA256SUMS`, `dependency-inventory.json` | Build twice, checksum diff, inventory readback and private Actions upload |
| B01 | CI-only HMAC issuer/audience/tenant/org/client, expiry, signature, sequence/replay/revocation | `packages/contracts/src/host-adapter-v15.ts` | Compiled contract code in runtime archives | `tests/phase15-host-contract.test.ts` |
| B02 | Unknown schema/capability, Host transport 401/403/408/409/429/5xx, production signer denial | Same | Same | CI-only contract negative tests |
| B03 | Real PostgreSQL16 service+worker+offline OpenAPI SPEC_ONLY→immutable report, SDK, wrong-tenant denial and restart | `scripts/phase15-packaged-e2e.mjs` | Installed service, worker, SDK | `Phase15 real PostgreSQL16 compiled API worker…` |
| B04 | Standalone UI read-only tenant/session/token switching, request fencing, renderer errors and accessible keyboard focus | `Phase15Mount.tsx`, `scripts/phase15-ui-archive-browser.mjs`, `tests/browser/phase15.spec.ts` | Installed UI package | Both Phase15 Chromium gates in Full |
| B05 | Unpushed nonroot, read-only, no-network OCI containers | `Dockerfile.phase15`, `scripts/phase15-container-smoke.sh` | CI-only local images | `Phase15 isolated unpushed OCI images…` |
| B06 | Full historical unit, PG16, Chromium, PDF, worker, supply-chain and RLS protection | Preserved Phase00–14 source/tests, `.github/workflows/phase15.yml` | Exact-HEAD CI evidence | All mandatory Full steps successful |
| B07 | Compatibility/operations, private release and Host handover | `docs/phase15-compatibility.json`, `docs/phase15-install-upgrade-recovery.md`, `docs/phase15-integration-handover.md` | Compatibility and release notes in private bundle | Source-to-requirement audit; final PR evidence |

**Source existence is never test success.** An individually passed test at an older SHA does not establish Level B. Full mandatory gates must be completed/success with zero failed or skipped mandatory Full steps at the current PR HEAD. Parent-level separately skipped optional jobs do not replace Full.

## Exact-head final qualification review instructions

1. Verify branch commit = PR head SHA = authoritative `[phase15-full]` run head SHA; verify merge status remains open/draft.
2. Read Full-job steps, use actual job logs for unit, PostgreSQL, Chromium and PDF counts, package E2E and OCI/container evidence.
3. Read `SHA256SUMS` and JSON manifest from uploaded private Actions artifact. Verify files, exact SHA-256 values, sizes, source commit and no forbidden paths; log artifact hashes in Full.
4. Verify immutable report, wrong-tenant deny and restart from **installed** archives, not the source-tree service.
5. Confirm all earlier security hardening including Phase14 LOW finding and Host gate stay intact.
6. Write the final actual evidence to PR description + one engineering comment and read both back independently.
7. Only then declare **LEVEL B ENGINEERING QUALIFIED; INDEPENDENT SECURITY ACCEPTANCE PENDING**.

## Level C / Main Platform Host blockers (not Level B failures)

The Host owner must supply approved production signing JWKS/issuer/audience, identity/membership/RBAC, tenant/client/asset ownership, permit request/revocation, entitlement and paid authority, canonical findings and RetestVerificationAuthority, event/webhook deliverability, hosted network/scope approvals, full production E2E and operational signoff. API Family must validate exact contracts and integrations; independent security reviewer must approve. No Host mock can lift these blocks.

See `docs/phase15-install-upgrade-recovery.md` for safe installation/upgrade, failure recovery, role separation and rollback; see `docs/phase15-integration-handover.md` for interface owners and risk.
