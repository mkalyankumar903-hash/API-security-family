# Phase 15 private release candidate — 0.15.0-rc.1

Status: **IN DEVELOPMENT / NOT YET VERIFIED**. Private artifacts only. No production deployment or Host-integrated trust. This candidate packages previously isolated security components, adds a provisional signed CI-only Host adapter simulator and a read-only React mount.

Accepted Phase14 source anchor: `418f07bd8efed24d6094b84ac71aacfac0097e54`. Preserve migrations 001–019 and all existing least-privilege boundaries.

Known nonblocking Phase14 LOW: repeated idempotent permit-revocation diagnostic may resemble a new state transition; not fixed.

Required independent Host integration: identity, membership, RBAC, real asset ownership, permits, entitlement snapshots, canonical findings, retest authority, events, hosted E2E, approval. No live scanning, billing, verification promotion or registry publishing.
