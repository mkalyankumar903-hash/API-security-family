import { migrate, closeDatabase } from "./index.js";
try { await migrate(); console.log("phase0 migration: applied"); }
catch (error) { console.error("migration failed:",error); process.exitCode = 1; }
finally { await closeDatabase(); }
