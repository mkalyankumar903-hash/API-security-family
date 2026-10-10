# LumicSec API Family v13 — isolated read-only SDK

> Private engineering artifact. **Do not publish to npm.** Main Platform commercial Host, production tenant/JWT delegation, billing and live scanning are **not configured**.

Node.js 22+ ESM and TypeScript. SDK emits Node.js ESM and `.d.ts` via `tsc --project packages/sdk/tsconfig.build.json`. GitHub Actions validates a private `npm pack --dry-run` artifact without publishing.

```typescript
import {V13Client} from "@lumicsec/api-family-v13-sdk";
const client = new V13Client({
  baseUrl:"http://127.0.0.1:3001",
  accessToken:async()=>getAuthorizedTestSessionToken()
});
const usage=await client.summary();
if(usage.hostAuthority==="HOST_AUTHORITY_NOT_CONFIGURED"){
  // Production Host contracts are missing: do not interpret synthetic quotas as billing authority.
}
```

The caller supplies authorized authentication and must never mint a fake production token. The SDK only supports GET reads: capabilities, entitlements, diagnostic deny decisions, usage, corrections, reservations and reconciliation. Sensitive responses use no-store; token string is never logged. Cancellation uses AbortSignal; timeouts are bounded. No writes exist, therefore neither write retries nor mutation idempotency keys are exposed as fictional functionality. Production support, public distribution and backwards compatibility beyond this isolated v13 contract remain deferred to authorized Host integration and Phase 15 handover.
