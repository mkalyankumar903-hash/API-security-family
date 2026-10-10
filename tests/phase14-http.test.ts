import {test} from "node:test";
import assert from "node:assert/strict";
import {makeApp} from "../packages/service/src/app.js";

test("Phase14 real Fastify HTTP rejects spoofing, oversized bodies and disallowed origins without leaking secrets",async()=>{
 const oldNode=process.env.NODE_ENV,oldFlag=process.env.SYNTHETIC_AUTH_ENABLED,
  oldTokens=process.env.DEV_TOKENS_JSON,oldDiag=process.env.API_FAMILY_DIAGNOSTICS;
 process.env.NODE_ENV="test";
 process.env.SYNTHETIC_AUTH_ENABLED="true";
 process.env.DEV_TOKENS_JSON=JSON.stringify({"this-is-a-valid-local-synthetic-token":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"});
 process.env.API_FAMILY_DIAGNOSTICS="true";
 const secret="Bearer never-log-this-secret";
 let app:Awaited<ReturnType<typeof makeApp>>|undefined;
 try{
  app=await makeApp();
  const live=await app.inject({method:"GET",url:"/health/live",
   headers:{"x-request-id":"attacker-injected-secret","origin":"https://attacker.invalid"}});
  assert.equal(live.statusCode,200);
  assert.equal(live.headers["cache-control"],"no-store");
  assert.equal(live.headers["x-content-type-options"],"nosniff");
  assert.equal(live.headers["x-frame-options"],"DENY");
  assert.equal(live.headers["access-control-allow-origin"],undefined);
  assert.equal(live.json().scope,"SPEC_ONLY");
  const missing=await app.inject({method:"GET",url:"/v13/capabilities",
   headers:{"x-tenant-id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}});
  assert.equal(missing.statusCode,401);
  assert.equal(missing.json().error,"UNAUTHORIZED");
  assert.equal(missing.headers["cache-control"],"no-store");
  assert(!missing.body.includes("attacker"));
  const forged=await app.inject({method:"GET",url:"/v13/capabilities",
   headers:{authorization:secret,"x-forwarded-for":"127.0.0.1",
    "x-tenant-id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}});
  assert.equal(forged.statusCode,403);
  assert.equal(forged.json().error,"PERMISSION_DENIED");
  assert(!forged.body.includes("never-log-this-secret"));
  const oversized=await app.inject({method:"POST",url:"/v1/targets",
   headers:{"content-type":"application/json",authorization:"Bearer this-is-a-valid-local-synthetic-token"},
   payload:"{\"secret\":\""+("A".repeat(1100000))+"\"}"});
  assert.equal(oversized.statusCode,413);
  assert.equal(oversized.json().error,"BODY_TOO_LARGE");
  assert.equal(oversized.headers["cache-control"],"no-store");
 }finally{
  await app?.close();
  for(const [key,value] of [["NODE_ENV",oldNode],["SYNTHETIC_AUTH_ENABLED",oldFlag],
   ["DEV_TOKENS_JSON",oldTokens],["API_FAMILY_DIAGNOSTICS",oldDiag]] as const){
   if(value===undefined)delete process.env[key];else process.env[key]=value;
  }
 }
});
