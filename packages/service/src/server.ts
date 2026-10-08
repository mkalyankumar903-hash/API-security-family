import { makeApp } from "./app.js";
import { pool } from "../../database/src/index.js";
const app = await makeApp();
const port = Number(process.env.PORT ?? 3001);
try {
  await pool.query("SELECT 1"); // readiness dependency before accepting customer traffic
  await app.listen({host:"127.0.0.1",port});
  console.log("API Family Phase 0 SPEC_ONLY server listening on 127.0.0.1:" + port);
} catch(e) { console.error("server startup failed", e instanceof Error ? e.message : "unknown"); process.exitCode=1; }
process.on("SIGTERM",async()=>{ await app.close(); await pool.end(); });
