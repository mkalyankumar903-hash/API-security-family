import { processOneJob } from "./index.js";
import { closeDatabase } from "../../database/src/index.js";
if (process.env.NODE_ENV === "production") throw new Error("HOST_AUTHORITY_NOT_CONFIGURED_PRODUCTION_FAIL_CLOSED");
let stopping = false;
process.on("SIGTERM",()=> { stopping=true; });
process.on("SIGINT",()=> { stopping=true; });
while (!stopping) {
  const didWork = await processOneJob().catch((error:unknown)=> { console.error("worker error",error instanceof Error ? error.name : "unknown"); return false; });
  if (!didWork) await new Promise(resolve => setTimeout(resolve, 300));
}
await closeDatabase();
