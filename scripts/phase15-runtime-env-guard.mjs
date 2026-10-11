/** CI-only pre-import assertion: executes INSIDE compiled service/worker process. */
import {writeFileSync} from "node:fs";
const privileged=/^(?:PG[A-Z0-9_]*|MIGRATION(?:_|$)|POSTGRES(?:_|$)|DB_ADMIN(?:_|$)|DATABASE_ADMIN(?:_|$)|SUPERUSER(?:_|$)|PHASE13_QA_DB_PASSWORD$)/i;
if(process.env.GITHUB_ACTIONS!=="true"||process.env.NODE_ENV!=="test"||
 process.env.SYNTHETIC_AUTH_ENABLED!=="true")throw Error("PHASE15_ENV_GUARD_CI_ONLY");
if(Object.keys(process.env).some(k=>privileged.test(k))||
 Object.values(process.env).some(v=>String(v).includes("local_admin_only")))
 throw Error("PHASE15_RUNTIME_PRIVILEGED_ENV_DENIED");
const a=new URL(process.env.DATABASE_URL??"invalid:");
const w=new URL(process.env.WORKER_DATABASE_URL??"invalid:");
if(a.username!=="api_family"||w.username!=="api_family_queue"||
 !["service","worker"].includes(process.env.PHASE15_ENV_ROLE??""))
 throw Error("PHASE15_RUNTIME_ROLE_BINDING_DENIED");
if(!process.env.PHASE15_ENV_PROOF_FILE)throw Error("PHASE15_ENV_PROOF_MISSING");
writeFileSync(process.env.PHASE15_ENV_PROOF_FILE,
 JSON.stringify({role:process.env.PHASE15_ENV_ROLE,compiledRuntime:true,privilegedEnvAbsent:true}));
