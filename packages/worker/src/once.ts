import { processOneJob } from "./index.js";
import { closeDatabase } from "../../database/src/index.js";
if (process.env.NODE_ENV === "production") throw new Error("HOST_AUTHORITY_NOT_CONFIGURED_PRODUCTION_FAIL_CLOSED");
try {
  const processed = await processOneJob();
  console.log("processed=" + processed);
} finally {
  await closeDatabase();
}
