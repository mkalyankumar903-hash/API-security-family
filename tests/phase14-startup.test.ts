/** Test actual node startup processes with hostile production configuration. */
import {test} from "node:test";
import assert from "node:assert/strict";
import {spawnSync} from "node:child_process";
const files=["packages/service/src/server.ts","packages/worker/src/main.ts","packages/worker/src/once.ts"];
test("Phase14 actual API/worker/one-shot production process never boots with synthetic or privileged test authority",()=>{
 for(const entry of files){
  const source="do-not-echo-phase14-secret-"+entry.replace(/\W/g,"");
  const result=spawnSync(process.execPath,["--import","tsx",entry],{
   encoding:"utf8",timeout:12000,maxBuffer:512000,
   env:{...process.env,NODE_ENV:"production",SYNTHETIC_AUTH_ENABLED:"true",
    DEV_TOKENS_JSON:JSON.stringify({[source]:"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}),
    PHASE1_SYNTHETIC_SIGNING_KEY:source,PT_TEST_SIGNING_KEY:source,
    PHASE13_QA_DB_PASSWORD:source,API_FAMILY_DIAGNOSTICS:"true",
    DATABASE_URL:"postgres://postgres:"+source+"@127.0.0.1:65530/api_family",
    WORKER_DATABASE_URL:"postgres://postgres:"+source+"@127.0.0.1:65530/api_family",
    MIGRATION_DATABASE_URL:"postgres://postgres:"+source+"@127.0.0.1:65530/api_family"}
  });
  assert.notEqual(result.status,0,"production process must never authorize synthetic startup "+entry);
  assert.match(String(result.stderr),/HOST_AUTHORITY_NOT_CONFIGURED_PRODUCTION_FAIL_CLOSED/,
   "reject at production authority guard before any network or DB login");
  assert(!String(result.stdout).includes("listening"));
  assert(!String(result.stderr).includes(source),"no secret values in boot failure");
 }
});
