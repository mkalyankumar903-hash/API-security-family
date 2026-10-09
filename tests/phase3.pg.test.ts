import {test} from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {makeApp} from "../packages/service/src/app.js";
import {migrate,pool,workerPool,withTenant} from "../packages/database/src/index.js";
import {drainQueue,processOneJob} from "../packages/worker/src/index.js";
const A="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const fixture=(name:string)=>readFileSync(new URL("../fixtures/"+name,import.meta.url),"utf8");
test("real PostgreSQL Phase03 four-format persisted queue, evidence, immutable reports, comparison, RLS and cancellation",async()=>{
 await migrate();const app=await makeApp(),uid=crypto.randomUUID().slice(0,8);
 const req=(method:"POST"|"GET",url:string,data?:unknown,token="local-test-token-alpha",key?:string)=>
 app.inject({method,url,headers:{authorization:"Bearer "+token,...(key?{"idempotency-key":key}:{})},payload:data as object|undefined});
 try{
  const target=await req("POST","/v1/targets",{name:"Detection "+uid,baseUrl:"https://detection-"+uid+".fixture.invalid",environment:"SYNTHETIC"});
  assert.equal(target.statusCode,201,target.body);const tid=target.json().id as string;
  const importFile=async(filename:string,content:string)=>{
   const r=await req("POST","/v2/targets/"+tid+"/specifications/imports",{filename,content},"local-test-token-alpha","import-"+crypto.randomUUID());
   assert.equal(r.statusCode,201,r.body);return r.json().specificationId as string;
  };
  const v1=await importFile("api-v1.json",fixture("phase2-openapi30-v1.json"));
  const v2=await importFile("api-v2.json",fixture("phase2-openapi30-v2.json"));
  const v31=await importFile("api-31.yaml",fixture("phase2-openapi31.yaml"));
  const swagger=await importFile("swagger.yaml",fixture("valid-swagger.yaml"));
  const postman=await importFile("postman.json",fixture("phase2-postman21.json"));
  assert.equal((await req("GET","/v3/detection/rules?limit=100")).json().length,28);
  assert.equal((await req("GET","/v3/detection/engines")).json()[0].networkRequestsAuthorized,0);
  const run=async(specificationId:string)=>{
   const key="detect-"+crypto.randomUUID(),url="/v3/targets/"+tid+"/assessments";
   const payload={specificationId,mode:"SPEC_ONLY",engineVersion:"inventory-v1"};
   const queued=await req("POST",url,payload,"local-test-token-alpha",key);
   assert.equal(queued.statusCode,201,queued.body);assert.equal(queued.json().networkRequestsAuthorized,0);
   assert.equal((await req("POST",url,payload,"local-test-token-alpha",key)).json().id,queued.json().id);
   const invalid=await req("POST",url,{...payload,specificationId:v1===specificationId?v2:v1},"local-test-token-alpha",key);
   assert.equal(invalid.statusCode,409);
   assert.equal(await drainQueue(),1);
   const jid=queued.json().id as string;
   const r=await req("GET","/v3/assessments/"+jid+"/report");
   assert.equal(r.statusCode,200,r.body);
   assert.equal(r.json().engineVersion,"inventory-v1");
   assert.ok(r.json().coverage.length===28);
   assert.equal(r.json().runtimeValidation,false);
   assert.deepEqual(r.json().confirmedVulnerabilities,[]);
   assert.ok(r.json().limitations.includes("UNKNOWN != SAFE"));
   return {jid,report:r.json(),body:r.body};
  };
  const first=await run(v1),again=await run(v1);
  assert.deepEqual(first.report.observations.map((x:{fingerprint:string})=>x.fingerprint),
   again.report.observations.map((x:{fingerprint:string})=>x.fingerprint));
  const second=await run(v2),third=await run(v31),fourth=await run(swagger),fifth=await run(postman);
  assert.ok(first.report.observationCount>0);
  assert.equal(fifth.report.warnings.includes("POSTMAN_SCRIPT_IGNORED"),true);
  assert.ok(!fifth.body.includes("test-secret-DO-NOT-PERSIST"));
  for(const runResult of [first,second,third,fourth,fifth]){
   const findings=await req("GET","/v3/assessments/"+runResult.jid+"/findings");
   assert.equal(findings.statusCode,200,findings.body);
   assert.equal(findings.json().length,runResult.report.observationCount);
   if(findings.json().length){
    const item=findings.json()[0];
    const detail=await req("GET","/v3/assessments/"+runResult.jid+"/findings/"+item.id);
    assert.equal(detail.statusCode,200,detail.body);assert.equal(detail.json().fingerprint,item.fingerprint);
    assert.match(detail.json().pointer,/^\//);
   }
   assert.equal((await req("GET","/v3/assessments/"+runResult.jid+"/coverage")).json().coverage.length,28);
   assert.equal((await req("GET","/v3/assessments/"+runResult.jid,"", "local-test-token-beta")).statusCode,404);
   assert.equal((await req("GET","/v3/assessments/"+runResult.jid+"/report",undefined,"local-test-token-beta")).statusCode,404);
   assert.equal((await req("GET","/v3/assessments/"+runResult.jid+"/findings",undefined,"local-test-token-beta")).statusCode,404);
  }
  const comparison=await req("POST","/v3/targets/"+tid+"/assessments/compare",{fromAssessmentId:first.jid,toAssessmentId:second.jid});
  assert.equal(comparison.statusCode,200,comparison.body);assert.equal(comparison.json().comparable,true);
  const unchanged=await req("GET","/v3/assessments/"+first.jid+"/report");
  assert.equal(unchanged.body,first.body,"historical report must be byte-for-byte immutable");
  const info=await withTenant(A,async tx=>tx.query("SELECT a.engine_version,a.inventory_fingerprint,count(f.id)::int AS findings FROM api_assessments a LEFT JOIN api_findings f ON f.assessment_id=a.id AND f.tenant_id=a.tenant_id WHERE a.id=$1 GROUP BY a.id",[first.jid]));
  assert.equal(info.rows[0].engine_version,"inventory-v1");
  assert.match(info.rows[0].inventory_fingerprint,/^[a-f0-9]{64}$/);
  assert.equal(info.rows[0].findings,first.report.observationCount);
  await assert.rejects(()=>withTenant(A,async tx=>tx.query("UPDATE api_reports SET projection='{}'::jsonb WHERE assessment_id=$1",[first.jid])),/PHASE1_IMMUTABLE/);
  assert.equal((await req("POST","/v3/targets/"+tid+"/assessments",{specificationId:v1,mode:"SPEC_ONLY",engineVersion:"legacy-v1"},"local-test-token-alpha","bad-"+crypto.randomUUID())).statusCode,400);
  const foreign=await req("POST","/v3/targets/"+tid+"/assessments",{specificationId:v1,mode:"SPEC_ONLY",engineVersion:"inventory-v1"},"local-test-token-beta","forged-"+crypto.randomUUID());
  assert.equal(foreign.statusCode,404);
  const cancelled=await req("POST","/v3/targets/"+tid+"/assessments",{specificationId:v1,mode:"SPEC_ONLY",engineVersion:"inventory-v1"},"local-test-token-alpha","cancel-"+crypto.randomUUID());
  assert.equal(cancelled.statusCode,201);
  const c=await req("POST","/v3/assessments/"+cancelled.json().id+"/cancel");assert.equal(c.statusCode,200,c.body);
  assert.equal((await req("GET","/v3/assessments/"+cancelled.json().id)).json().status,"CANCELLED");
  assert.equal((await req("GET","/v3/assessments/"+cancelled.json().id+"/report")).statusCode,404);
  assert.deepEqual((await Promise.all([processOneJob(),processOneJob()])),[false,false]);
  const rev=(await req("GET","/v1/targets/"+tid)).json().revision as number;
  assert.equal((await app.inject({method:"POST",url:"/v1/targets/"+tid+"/lifecycle",headers:{authorization:"Bearer local-test-token-alpha"},
   payload:{revision:rev,action:"SUSPEND"}})).statusCode,200);
  assert.equal((await req("POST","/v3/targets/"+tid+"/assessments",{specificationId:v1,mode:"SPEC_ONLY",engineVersion:"inventory-v1"},"local-test-token-alpha","suspend-"+crypto.randomUUID())).statusCode,409);
 }finally{await app.close();await pool.end();await workerPool.end();}
});
