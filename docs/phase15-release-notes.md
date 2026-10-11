# LumicSec API Family — private release candidate 0.15.0-rc.1

This is a **private isolated Level B engineering candidate only**, not a publicly published, customer-ready, hosted or production-Host authorized product. Level B engineering status is determined only by exact-HEAD GitHub Full CI and the PR #16 evidence comment.

Changes compared with accepted Phase14: compiled Node22 Fastify service and dedicated private worker packages; private SDK ESM + declarations; reusable read-only React mount with error containment; forward-only PostgreSQL16 migrations 001–019 archived unchanged; draft v15 CI-only Host contract and negative security tests; reproducible SHA-256 signed-by-hash inventory; clean install, actual packaged assessment and Chromium consumer, unpushed nonroot container smoke; operations/handover documents.

Included private artifacts: `api-service.tar.gz`, `api-worker.tar.gz`, `sdk-private.tgz`, `ui-private.tgz`, `postgres16-migrations-001-019.tar.gz`, `contract-schemas-draft.tar.gz`, `manifest.json`, `SHA256SUMS`, `dependency-inventory.json`, `compatibility.json`, `release-notes.md`. SHA256SUMS covers constituent files; manifest binds the Git source SHA. Integrity hashes are **not** cryptographic release signatures.

Breaking/limited compatibility: production Host integration remains disabled; v0.3.2 upstream definitions provisional; CI-only synthetic fixtures never authorize production. No customer scans, payment authority, Host permits, canonical findings authority, SDK/npm/OCI/public publication, or migration reset.

Known Phase14 **LOW** outstanding: idempotent repeated permit-revocation diagnostic can be read as a new state transition. Not fixed.

Safe setup, upgrade, backup/restore, incident, deploy restrictions and Host responsibilities: `docs/phase15-install-upgrade-recovery.md` and `docs/phase15-integration-handover.md`.
