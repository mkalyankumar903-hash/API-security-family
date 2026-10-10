import {test} from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {randomUUID} from "node:crypto";
import {migrate,pool,withTenant,withWorkerTenant,claimJob,closeDatabase} from "../packages/database/src/index.js";
import {makeApp} from "../packages/service/src/app.js";
import {processOneJob} from "../packages/worker/src/index.js";
import {processAutonomousVaptJob} from "../packages/worker/src/autonomous-vapt.js";

const A="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",B="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const SOURCE=readFileSync(new URL("../fixtures/phase07-security.openapi.json",import.meta.url),"utf8");
const RULE_PATHS=["/pt/account","/pt/resources/bob","/pt/admin","/pt/confidential"];
type Api={statusCode:number;body:string;json:()=>Record<string,unknown>};
test("Phase11 real PostgreSQL: offline then signed-governed child then atomic unified parent report",async()=>{
 await migrate();const app=await makeApp();
 const call=(method:"GET"|"POST",url:string,payload?:unknown,opts?:{key?:string;token?:string;authority?:boolean})=>
  app.inject({method,url,payload:payload as object|undefined,headers:{
   authorization:"Bearer "+(opts?.token??"local-test-token-alpha"),
   ...(opts?.key?{"idempotency-key":opts.key}:{}),
   ...(opts?.authority?{"x-pt-authority-key":process.env.PT_TEST_AUTHORITY_KEY??""}:{})
  }}) as Promise<Api>;
 const ok=(r:Api,status:number)=>assert.equal(r.statusCode,status,r.body);
 try{
  const migration=await pool.query("SELECT version FROM api_schema_migrations WHERE version='015'");
  assert.equal(migration.rowCount,1);
  const tables=await pool.query("SELECT relname,relrowsecurity,relforcerowsecurity FROM pg_class WHERE relname LIKE 'api_vapt11_%' AND relkind='r'");
  assert.equal(tables.rowCount,5);assert(tables.rows.every(x=>x.relrowsecurity&&x.relforcerowsecurity));
  const name=randomUUID().slice(0,8);
  const t=await call("POST","/v1/targets",{name:"Vapt11 "+name,environment:"SYNTHETIC",baseUrl:"https://vapt11-"+name+".fixture.invalid"});ok(t,201);
  const tid=t.json().id as string;
  const imp=await call("POST","/v2/targets/"+tid+"/specifications/imports",
   {filename:"phase07-security.openapi.json",content:SOURCE},{key:"vapt11-import-"+randomUUID()});ok(imp,201);
  const specId=imp.json().specificationId as string;
  const ops=await call("GET","/v2/specifications/"+specId+"/operations?limit=100");ok(ops,200);
  const operationKeys=RULE_PATHS.map(path=>
   (ops.json() as unknown as {key:string;method:string;path:string}[])
    .find(x=>x.path===path&&x.method==="GET")?.key);
  assert(operationKeys.every(Boolean));
  const scopes=await call("POST","/v6/pt/targets/"+tid+"/scopes",{
   specificationId:specId,operationKeys,fixtureId:"pt-security-v1",exclusions:[],
   maxEvaluations:14,ratePerMinute:14,maxConcurrency:1,deadlineMs:30000,validityMinutes:15
  },{key:"vapt11-scope-"+randomUUID()});ok(scopes,201);
  const sid=scopes.json().id as string;
  const unsigned=await call("POST","/v11/api-vapt/assessments",{
   mode:"GOVERNED_SYNTHETIC",scopeId:sid,policyId:"SYNTHETIC_PT_COMPLETE_SUPPORTED",profile:"SECURE_BASELINE"
  },{key:"vapt11-unsigned-"+randomUUID()});ok(unsigned,409);
  ok(await call("POST","/v6/pt/scopes/"+sid+"/request-authorization",{}),201);
  ok(await call("POST","/v6/pt/test-authority/scopes/"+sid+"/issue",{}, {authority:true}),201);
  const preview=await call("GET","/v11/api-vapt/scopes/"+sid+"/preview?policyId=SYNTHETIC_PT_COMPLETE_SUPPORTED&profile=SECURE_BASELINE");
  ok(preview,200);assert.equal(preview.json().authorizationReady,true,preview.body);
  const idem="vapt11-parent-"+randomUUID();
  const payload={mode:"GOVERNED_SYNTHETIC",scopeId:sid,policyId:"SYNTHETIC_PT_COMPLETE_SUPPORTED",profile:"SECURE_BASELINE"};
  const created=await call("POST","/v11/api-vapt/assessments",payload,{key:idem});ok(created,201);
  const parent=created.json().id as string;
  // Even the private worker database role cannot manufacture successful parent
  // publication before real completed offline + PT component evidence.
  const forged={schemaVersion:"autonomous-api-vapt-report-v1",assessmentId:parent,
   offlineAssessmentId:created.json().offlineAssessmentId,
   ptAssessmentId:created.json().ptAssessmentId,mode:"GOVERNED_SYNTHETIC",
   fullAuthorizedVaptCompleted:true,planFingerprint:created.json().planFingerprint,
   status:"COMPLETED",syntheticOnly:true,verifiedFixed:false,customerRuntimeVerified:false,customerNetworkRequests:0};
  await assert.rejects(()=>withWorkerTenant(A,tx=>tx.query(
   "INSERT INTO api_vapt11_reports(id,tenant_id,parent_assessment_id,projection,fingerprint) VALUES($1,$2,$3,$4::jsonb,$5)",
   [randomUUID(),A,parent,JSON.stringify(forged),"a".repeat(64)])),/VAPT11_OFFLINE_OR_PARENT_NOT_COMPLETE/);

  const duplicated=await call("POST","/v11/api-vapt/assessments",payload,{key:idem});ok(duplicated,200);
  assert.equal(duplicated.json().id,parent);
  assert.equal((await call("GET","/v11/api-vapt/assessments/"+parent)).json().status,"QUEUED");
  assert.equal((await call("GET","/v11/api-vapt/assessments/"+parent,undefined,{token:"local-test-token-beta"})).statusCode,404);
  assert.equal(await processOneJob(),true,"offline child must execute");
  const partial=await call("GET","/v11/api-vapt/assessments/"+parent);ok(partial,200);
  const children=partial.json().children as {engine_version:string;status:string}[];
  assert.equal(children.find(x=>x.engine_version.startsWith("inventory-"))?.status,"COMPLETED",partial.body);
  assert.equal(children.find(x=>x.engine_version==="pt-orchestrator-v1")?.status,"QUEUED");
  assert.equal((await call("GET","/v11/api-vapt/assessments/"+parent+"/report")).statusCode,409);
  assert.equal(await processOneJob(),true,"governed Phase09 child must execute");
  assert.equal(await processOneJob(),true,"parent reporting must execute");
  const final=await call("GET","/v11/api-vapt/assessments/"+parent);ok(final,200);
  assert.equal(final.json().status,"COMPLETED",final.body);
  const report=await call("GET","/v11/api-vapt/assessments/"+parent+"/report");ok(report,200);
  assert.equal(report.json().status,"COMPLETED");
  assert.equal(report.json().syntheticOnly,true);
  assert.equal(report.json().verifiedFixed,false);
  assert.equal(report.json().customerRuntimeVerified,false);
  assert.equal((report.json().pt as {executedEvaluations:number}).executedEvaluations,14);
  assert.equal((report.json().components as {status:string}[]).length,2);
  assert((report.json().components as {status:string}[]).every(x=>x.status==="COMPLETED"));
  ok(await call("GET","/v11/api-vapt/assessments/"+parent+"/export"),200);
  ok(await call("GET","/v11/api-vapt/assessments/"+parent+"/findings?limit=20"),200);
  assert.equal((await call("GET","/v11/api-vapt/assessments/"+parent+"/report",undefined,{token:"local-test-token-beta"})).statusCode,409);
  const historical=await call("GET","/v11/api-vapt/targets/"+tid+"/history?limit=10");ok(historical,200);
  assert((historical.json() as unknown as {id:string}[]).some(x=>x.id===parent));
  const reassess=await call("POST","/v11/api-vapt/assessments/"+parent+"/reassess",{}, {key:"vapt11-reassess-"+randomUUID()});
  ok(reassess,409); // original signed permit budget is exhausted; never refresh authority.
  // Legitimate safe reassessment: a NEW, separately scoped and signed test
  // authorization rebinds a fresh child graph to preserved parent lineage.
  const newScope=await call("POST","/v6/pt/targets/"+tid+"/scopes",{
   specificationId:specId,operationKeys,fixtureId:"pt-security-v1",exclusions:[],
   maxEvaluations:14,ratePerMinute:14,maxConcurrency:1,deadlineMs:30000,validityMinutes:15
  },{key:"vapt11-fresh-scope-"+randomUUID()});ok(newScope,201);
  const newSid=newScope.json().id as string;
  ok(await call("POST","/v6/pt/scopes/"+newSid+"/request-authorization",{}),201);
  ok(await call("POST","/v6/pt/test-authority/scopes/"+newSid+"/issue",{}, {authority:true}),201);
  const second=await call("POST","/v11/api-vapt/assessments/"+parent+"/reassess",{scopeId:newSid},
   {key:"vapt11-authorized-retest-"+randomUUID()});ok(second,201);
  const secondId=second.json().id as string;
  assert.notEqual(secondId,parent);
  for(let i=0;i<3;i++)assert.equal(await processOneJob(),true);
  const secondReport=await call("GET","/v11/api-vapt/assessments/"+secondId+"/report");
  ok(secondReport,200);assert.equal(secondReport.json().verifiedFixed,false);
  const lineage=await call("GET","/v11/api-vapt/assessments/"+secondId);ok(lineage,200);
  assert.equal(lineage.json().lineage_parent_id,parent);
  const oldReport=await call("GET","/v11/api-vapt/assessments/"+parent+"/report");
  ok(oldReport,200);
  assert.equal((oldReport.json() as {ptAssessmentId:string}).ptAssessmentId,created.json().ptAssessmentId);
  const compare=await call("GET","/v11/api-vapt/assessments/"+parent+"/compare/"+secondId);
  ok(compare,200);
  assert.equal(compare.json().compatibility,"INCOMPATIBLE","different authority scopes cannot be treated as equivalent observations");


  await assert.rejects(()=>withTenant(A,tx=>tx.query("UPDATE api_vapt11_reports SET fingerprint=$1 WHERE parent_assessment_id=$2",["a".repeat(64),parent])),
   /permission denied|immutable/i);
  const isolated=await withTenant(B,tx=>tx.query("SELECT * FROM api_vapt11_reports WHERE parent_assessment_id=$1",[parent]));
  assert.equal(isolated.rowCount,0);

  const offline=await call("POST","/v11/api-vapt/assessments",{
   mode:"OFFLINE_ONLY",targetId:tid,specificationId:specId},{key:"vapt11-offline-"+randomUUID()});ok(offline,201);
  const offlineParent=offline.json().id as string;
  assert.equal(await processOneJob(),true);
  assert.equal(await processOneJob(),true);
  const offlineReport=await call("GET","/v11/api-vapt/assessments/"+offlineParent+"/report");ok(offlineReport,200);
  assert.equal(offlineReport.json().fullAuthorizedVaptCompleted,false);
  assert.equal((offlineReport.json().pt as {executedEvaluations:number}).executedEvaluations,0);
  assert.equal((offlineReport.json().coverage as {ptNotTested:boolean}).ptNotTested,true);
  // Phase11-specific real-PostgreSQL crash/takeover qualification at the exact
  // parent publication boundary. A former worker must never publish.
  const recovery=await call("POST","/v11/api-vapt/assessments",{
   mode:"OFFLINE_ONLY",targetId:tid,specificationId:specId},{key:"vapt11-recovery-"+randomUUID()});
  ok(recovery,201);
  const recoveryId=recovery.json().id as string;
  assert.equal(await processOneJob(),true,"recovery offline child is authoritative");
  const stale=await claimJob();assert.equal(stale?.assessment_id,recoveryId);
  await withWorkerTenant(A,tx=>tx.query(
   "UPDATE api_queue.api_assessment_queue SET locked_until=clock_timestamp()-interval '1 second' WHERE assessment_id=$1",[recoveryId]));
  const replacement=await claimJob();assert.equal(replacement?.assessment_id,recoveryId);
  assert.notEqual(stale!.claim_token,replacement!.claim_token);
  await assert.rejects(()=>processAutonomousVaptJob(A,recoveryId,stale!.claim_token),
   /VAPT11_PARENT_LEASE_LOST/,"stale generation cannot publish immutable report");
  await processAutonomousVaptJob(A,recoveryId,replacement!.claim_token);
  const recovered=await call("GET","/v11/api-vapt/assessments/"+recoveryId+"/report");
  ok(recovered,200);
  assert.equal((recovered.json() as {status:string}).status,"COMPLETED");
  assert.equal((await withTenant(A,tx=>tx.query(
   "SELECT count(*)::int AS n FROM api_vapt11_reports WHERE parent_assessment_id=$1",[recoveryId]))).rows[0].n,1);

  const cancel=await call("POST","/v11/api-vapt/assessments",{
   mode:"OFFLINE_ONLY",targetId:tid,specificationId:specId},{key:"vapt11-cancel-"+randomUUID()});ok(cancel,201);
  const cid=cancel.json().id as string;
  const cancelled=await call("POST","/v11/api-vapt/assessments/"+cid+"/cancel",{});ok(cancelled,200);
  assert.equal(cancelled.json().status,"CANCELLED");
  assert.equal((await call("GET","/v11/api-vapt/assessments/"+cid+"/report")).statusCode,409);
  ok(await call("GET","/v11/api-vapt/assessments/"+cid+"/terminal"),200);
 }finally{await app.close();await closeDatabase();}
});
