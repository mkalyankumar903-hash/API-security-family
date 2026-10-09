import {test} from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {makeApp} from "../packages/service/src/app.js";
import {migrate,pool,workerPool,withTenant} from "../packages/database/src/index.js";
import {drainQueue,processOneJob} from "../packages/worker/src/index.js";
const A="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",B="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
test("Phase04 real PostgreSQL 16: fixture profiles, actual worker eval, immutable evidence and cross-tenant protection",async()=>{
 await migrate();const app=await makeApp();
 const invoke=(method:"GET"|"POST"|"PATCH",url:string,payload?:unknown,token="local-test-token-alpha",idem?:string)=>
  app.inject({method,url,headers:{authorization:"Bearer "+token,...(idem?{"idempotency-key":idem}:{})},payload:payload as object|undefined});
 try{
  const name=crypto.randomUUID().slice(0,8);
  const t=await invoke("POST","/v1/targets",{name:"Auth "+name,baseUrl:"https://auth-"+name+".fixture.invalid",environment:"SYNTHETIC"});
  assert.equal(t.statusCode,201,t.body);const targetId=t.json().id as string;
  const file=readFileSync(new URL("../fixtures/phase2-openapi30-v1.json",import.meta.url),"utf8");
  const imported=await invoke("POST","/v2/targets/"+targetId+"/specifications/imports",{filename:"auth.json",content:file},"local-test-token-alpha","auth-import-"+name);
  assert.equal(imported.statusCode,201,imported.body);const specId=imported.json().specificationId as string;
  const cref="credref:auth_fixture_"+name;
  const cr=await invoke("POST","/v1/targets/"+targetId+"/credentials",{revision:1,reference:cref});
  assert.equal(cr.statusCode,201,cr.body);
  const create=async(fixtureVersion:string,scheme:string="BEARER")=>invoke("POST","/v4/targets/"+targetId+"/profiles",
   {specificationId:specId,fixtureVersion,scheme,identityKey:"user-a",credentialReference:cref});
  const secure=await create("secure-v1");assert.equal(secure.statusCode,201,secure.body);
  const sp=secure.json().id as string;
  assert.ok(Date.parse(secure.json().expiresAt as string)>Date.now(),"synthetic profile gets bounded expiry metadata");
  assert.equal((await invoke("POST","/v4/profiles/"+sp+"/validate",{revision:1})).json().ready,true);
  const run=async(pid:string,revision:number)=>{
   const config={specificationId:specId,profileId:pid,profileRevision:revision,engineVersion:"auth-fixture-v1",analysisProfile:"SYNTHETIC_AUTH_FIXTURE",mode:"SPEC_ONLY"};
   const idem="auth04-"+crypto.randomUUID(),url="/v4/targets/"+targetId+"/assessments";
   const admitted=await invoke("POST",url,config,"local-test-token-alpha",idem);
   assert.equal(admitted.statusCode,201,admitted.body);
   const jobId=admitted.json().id as string;
   assert.equal((await invoke("POST",url,config,"local-test-token-alpha",idem)).json().id,jobId);
   const collision=await invoke("POST",url,{...config,profileRevision:revision+1},"local-test-token-alpha",idem);
   assert.equal(collision.statusCode,409);
   assert.equal(await drainQueue(),1);
   const report=await invoke("GET","/v4/assessments/"+jobId+"/report");
   assert.equal(report.statusCode,200,report.body);
   assert.equal(report.json().engineVersion,"auth-fixture-v1");
   assert.equal(report.json().evaluationCount,21);
   assert.equal(report.json().customerNetworkRequests,0);
   assert.deepEqual(report.json().confirmedCustomerVulnerabilities,[]);
   assert.equal((await invoke("GET","/v4/assessments/"+jobId+"/evaluations")).json().length,21);
   assert.equal((await invoke("GET","/v4/assessments/"+jobId+"/coverage")).json().coverage.attempted,21);
   assert.equal((await invoke("GET","/v4/assessments/"+jobId+"/report",undefined,"local-test-token-beta")).statusCode,404);
   assert.equal((await invoke("GET","/v4/assessments/"+jobId+"/evaluations",undefined,"local-test-token-beta")).statusCode,404);
   return {jobId,report:report.json(),body:report.body};
  };
  const a=await run(sp,1);assert.equal(a.report.observationCount,0);
  assert.equal((await invoke("POST","/v4/targets/"+targetId+"/assessments",
   {specificationId:specId,profileId:sp,profileRevision:1,engineVersion:"auth-fixture-v1",analysisProfile:"SYNTHETIC_AUTH_FIXTURE",mode:"SPEC_ONLY"},
   "local-test-token-beta","forged-"+crypto.randomUUID())).statusCode,404);
  const bad=await create("broken-bola-v1","OAUTH2");assert.equal(bad.statusCode,201,bad.body);
  const bp=bad.json().id as string;
  assert.equal((await invoke("POST","/v4/profiles/"+bp+"/validate",{revision:1})).json().ready,true);
  const b=await run(bp,1);assert.equal(b.report.observationCount,1);
  assert.equal(b.report.observations[0].ruleId,"AUTH04_CROSS_USER_BOLA");
  assert.equal(b.report.observations[0].validationLevel,"SYNTHETIC_AUTH_FIXTURE");
  assert.equal(b.report.runtimeValidation,false);
  const item=(await invoke("GET","/v4/assessments/"+b.jobId+"/findings")).json()[0];
  assert.equal(item.validationLevel,"SYNTHETIC_AUTH_FIXTURE");
  assert.equal((await invoke("GET","/v4/assessments/"+b.jobId+"/evidence/"+item.evidenceId)).statusCode,200);
  const text=b.body+JSON.stringify(item);
  assert.ok(!/Bearer [A-Za-z0-9_-]{20,}|fixture_session=|Basic [A-Za-z0-9+/=]{10,}/.test(text));
  const cmp=await invoke("POST","/v4/targets/"+targetId+"/assessments/compare",{fromAssessmentId:a.jobId,toAssessmentId:b.jobId});
  assert.equal(cmp.statusCode,200,cmp.body);assert.equal(cmp.json().newlyObserved.length,1);
  assert.equal((await invoke("GET","/v4/assessments/"+a.jobId+"/report")).body,a.body);
  assert.equal((await invoke("POST","/v4/profiles/"+bp+"/revoke",{revision:1})).statusCode,200);
  assert.equal((await invoke("POST","/v4/profiles/"+bp+"/validate",{revision:2})).json().ready,false);
  assert.equal((await invoke("POST","/v4/targets/"+targetId+"/assessments",
   {specificationId:specId,profileId:bp,profileRevision:2,engineVersion:"auth-fixture-v1",analysisProfile:"SYNTHETIC_AUTH_FIXTURE",mode:"SPEC_ONLY"},
   "local-test-token-alpha","revoked-"+crypto.randomUUID())).statusCode,409);
  const queued=await invoke("POST","/v4/targets/"+targetId+"/assessments",
   {specificationId:specId,profileId:sp,profileRevision:1,engineVersion:"auth-fixture-v1",analysisProfile:"SYNTHETIC_AUTH_FIXTURE",mode:"SPEC_ONLY"},
   "local-test-token-alpha","cancel-"+crypto.randomUUID());
  assert.equal(queued.statusCode,201,queued.body);
  assert.equal((await invoke("POST","/v4/assessments/"+queued.json().id+"/cancel")).statusCode,200);
  assert.equal((await invoke("GET","/v4/assessments/"+queued.json().id+"/report")).statusCode,404);
  assert.equal(await processOneJob(),false);
  const state=await withTenant(A,tx=>tx.query("SELECT (SELECT COUNT(*)::int FROM api_auth_evaluations WHERE assessment_id=$1) AS evals,(SELECT COUNT(*)::int FROM api_findings WHERE assessment_id=$1) AS findings",[b.jobId]));
  assert.equal(state.rows[0].evals,21);assert.equal(state.rows[0].findings,1);
  await assert.rejects(()=>withTenant(A,tx=>tx.query("UPDATE api_reports SET projection='{}'::jsonb WHERE assessment_id=$1",[a.jobId])),/PHASE1_IMMUTABLE/);
  await assert.rejects(()=>withTenant(A,tx=>tx.query("DELETE FROM api_auth_evaluations WHERE assessment_id=$1",[b.jobId])),/permission denied|PHASE1_IMMUTABLE/);
  // Simulated time passage: a profile which has expired must fail closed, even
  // when the last readiness validation was previously VALID.
  await withTenant(A,tx=>tx.query("UPDATE api_auth_profiles SET expires_at=now()-interval '1 minute' WHERE id=$1",[sp]));
  const expiredCheck=await invoke("POST","/v4/profiles/"+sp+"/validate",{revision:1});
  assert.equal(expiredCheck.statusCode,200,expiredCheck.body);
  assert.equal(expiredCheck.json().ready,false);
  assert.ok(expiredCheck.json().reasons.includes("PROFILE_EXPIRED"));
  const expiredAdmission=await invoke("POST","/v4/targets/"+targetId+"/assessments",
   {specificationId:specId,profileId:sp,profileRevision:1,engineVersion:"auth-fixture-v1",analysisProfile:"SYNTHETIC_AUTH_FIXTURE",mode:"SPEC_ONLY"},
   "local-test-token-alpha","expired-"+crypto.randomUUID());
  assert.equal(expiredAdmission.statusCode,409,expiredAdmission.body);
  const foreign=await withTenant(B,tx=>tx.query("SELECT count(*)::int AS n FROM api_auth_profiles"));
  assert.equal(foreign.rows[0].n,0);
  const real=await invoke("POST","/v1/targets",{name:"Production denied",baseUrl:"https://prod-"+name+".fixture.invalid",environment:"PRODUCTION"});
  assert.equal(real.statusCode,201);
  const unsafe=await invoke("POST","/v4/targets/"+real.json().id+"/profiles",
   {specificationId:specId,fixtureVersion:"secure-v1",scheme:"BEARER",identityKey:"admin",credentialReference:cref});
  assert.equal(unsafe.statusCode,403);
 }finally{await app.close();await pool.end();await workerPool.end();}
});
