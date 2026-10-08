import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { migrate,withTenant,pool } from "../packages/database/src/index.js";
import { makeApp } from "../packages/service/src/app.js";
import { drainQueue } from "../packages/worker/src/index.js";

const A="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", B="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const TOKEN_A="local-test-token-alpha", TOKEN_B="local-test-token-beta";
const headers=(token=TOKEN_A)=>({ authorization:"Bearer "+token });
const insecure=readFileSync(new URL("../fixtures/insecure.openapi.json",import.meta.url),"utf8");
const secure=readFileSync(new URL("../fixtures/secure.openapi.json",import.meta.url),"utf8");
test("full real PostgreSQL customer workflow, isolation, restart and cancellation",async()=>{
  process.env.SYNTHETIC_AUTH_ENABLED="true";
  process.env.DEV_TOKENS_JSON=JSON.stringify({[TOKEN_A]:A,[TOKEN_B]:B});
  await migrate();
  const app=await makeApp();
  try {
    const unauth=await app.inject({method:"GET",url:"/v1/targets"});
    assert.equal(unauth.statusCode,401);
    const forged=await app.inject({method:"GET",url:"/v1/targets",headers:headers("forged-token")});
    assert.equal(forged.statusCode,403);
    for(const bad of ["http://127.0.0.1","https://169.254.169.254/latest/meta-data","http://api.fixture.invalid"]) {
      const r=await app.inject({method:"POST",url:"/v1/targets",headers:headers(),payload:{name:"Unsafe",baseUrl:bad,environment:"SYNTHETIC"}});
      assert.equal(r.statusCode,400);
    }
    const target=await app.inject({method:"POST",url:"/v1/targets",headers:headers(),payload:{name:"Fixture API",baseUrl:"https://api.fixture.invalid",environment:"SYNTHETIC"}});
    assert.equal(target.statusCode,201,target.body);
    const targetId=target.json().id as string;
    assert.equal((await app.inject({method:"GET",url:"/v1/targets/"+targetId,headers:headers(TOKEN_B)})).statusCode,404);
    const malformed=await app.inject({method:"POST",url:"/v1/targets/"+targetId+"/specifications",headers:headers(),payload:{filename:"bad.yaml",content:"openapi: 3.0.0\npaths: {}"}});
    assert.equal(malformed.statusCode,422);
    const upload=await app.inject({method:"POST",url:"/v1/targets/"+targetId+"/specifications",headers:headers(),payload:{filename:"fixture.json",content:insecure}});
    assert.equal(upload.statusCode,201,upload.body);
    const specId=upload.json().id as string;
    assert.equal(upload.json().operationCount,3);
    const ops=await app.inject({method:"GET",url:"/v1/specifications/"+specId+"/operations",headers:headers()});
    assert.equal(ops.json().length,3);
    assert.equal((await app.inject({method:"GET",url:"/v1/specifications/"+specId+"/operations",headers:headers(TOKEN_B)})).json().length,0);
    const idempotency="test-synthetic-"+crypto.randomUUID();
    const started=await app.inject({method:"POST",url:"/v1/targets/"+targetId+"/assessments",headers:{...headers(),"idempotency-key":idempotency},payload:{specificationId:specId,mode:"SPEC_ONLY"}});
    assert.equal(started.statusCode,201,started.body);
    const assessmentId=started.json().id as string;
    const retried=await app.inject({method:"POST",url:"/v1/targets/"+targetId+"/assessments",headers:{...headers(),"idempotency-key":idempotency},payload:{specificationId:specId,mode:"SPEC_ONLY"}});
    assert.equal(retried.json().id,assessmentId);
    assert.equal((await app.inject({method:"GET",url:"/v1/assessments/"+assessmentId,headers:headers(TOKEN_B)})).statusCode,404);
    assert.equal((await app.inject({method:"GET",url:"/v1/assessments/"+assessmentId+"/report",headers:headers(TOKEN_B)})).statusCode,404);
    assert.equal(await drainQueue(),1);
    const status=await app.inject({method:"GET",url:"/v1/assessments/"+assessmentId,headers:headers()});
    assert.equal(status.json().status,"COMPLETED");
    const report=await app.inject({method:"GET",url:"/v1/assessments/"+assessmentId+"/report",headers:headers()});
    assert.equal(report.statusCode,200,report.body);
    assert.equal(report.json().operationsAssessed,3);
    assert.ok(report.json().observationCount > 0);
    assert.equal(report.json().coverage.runtimeValidation,false);
    assert.ok(report.json().limitations.includes("UNKNOWN != SAFE"));
    const found=await app.inject({method:"GET",url:"/v1/assessments/"+assessmentId+"/findings",headers:headers()});
    assert.ok(found.json().every((f:{ evidenceId:string;validationLevel:string })=>!!f.evidenceId&&f.validationLevel==="SPEC_ONLY"));
    assert.equal((await app.inject({method:"GET",url:"/v1/assessments/"+assessmentId+"/findings",headers:headers(TOKEN_B)})).json().length,0);
    assert.equal(await drainQueue(),0);
    // RLS also holds under separate actual connections, without browser-derived tenancy.
    const separate=await pool.connect();
    try {
      const r=await separate.query("SELECT count(*)::int AS count FROM api_targets WHERE id=$1",[targetId]);
      assert.equal(r.rows[0].count,0);
    } finally { separate.release(); }
    const tenantBRecords=await withTenant(B,async tx=>(await tx.query("SELECT id FROM api_targets WHERE id=$1",[targetId])).rows);
    assert.equal(tenantBRecords.length,0);
    const second=await app.inject({method:"POST",url:"/v1/targets/"+targetId+"/specifications",headers:headers(),payload:{filename:"clean.json",content:secure}});
    assert.equal(second.statusCode,201);
    const start2=await app.inject({method:"POST",url:"/v1/targets/"+targetId+"/assessments",headers:{...headers(),"idempotency-key":"clean-"+crypto.randomUUID()},payload:{specificationId:second.json().id,mode:"SPEC_ONLY"}});
    assert.equal(start2.statusCode,201);
    await drainQueue();
    const report2=await app.inject({method:"GET",url:"/v1/assessments/"+start2.json().id+"/report",headers:headers()});
    assert.equal(report2.json().observationCount,0);
    const start3=await app.inject({method:"POST",url:"/v1/targets/"+targetId+"/assessments",headers:{...headers(),"idempotency-key":"cancel-"+crypto.randomUUID()},payload:{specificationId:specId,mode:"SPEC_ONLY"}});
    const cancelled=await app.inject({method:"POST",url:"/v1/assessments/"+start3.json().id+"/cancel",headers:headers()});
    assert.equal(cancelled.statusCode,200);
    assert.equal(await drainQueue(),0);
    assert.equal((await app.inject({method:"GET",url:"/v1/assessments/"+start3.json().id,headers:headers()})).json().status,"CANCELLED");
  } finally {await app.close();await pool.end();}
});
