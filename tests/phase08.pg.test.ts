import {test} from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {randomUUID} from "node:crypto";
import {migrate,pool,withTenant,withWorkerTenant,claimJob,closeDatabase} from "../packages/database/src/index.js";
import {makeApp} from "../packages/service/src/app.js";
import {processOneJob} from "../packages/worker/src/index.js";
import {processPtDetectionJob} from "../packages/worker/src/pt-detection.js";
const A="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",AUTH="local-test-token-alpha";
const SIGNER=process.env.PT_TEST_AUTHORITY_KEY??"";
const source=readFileSync(new URL("../fixtures/phase07-security.openapi.json",import.meta.url),"utf8");
type API={statusCode:number;body:string;json:()=>Record<string,unknown>};

test("Phase08 real PostgreSQL: migration 012, terminal persistence, fault recovery and strict isolation",async()=>{
 await migrate();
 const app=await makeApp();
 async function call(method:"GET"|"POST",url:string,data?:unknown,opts?:{key?:string;token?:string;authority?:boolean}):Promise<API>{
  return app.inject({method,url,payload:data as object|undefined,
   headers:{authorization:"Bearer "+(opts?.token??AUTH),
    ...(opts?.key?{"idempotency-key":opts.key}:{}),
    ...(opts?.authority?{"x-pt-authority-key":SIGNER}:{})}});
 }
 try{
  const q=await pool.query("SELECT version FROM api_schema_migrations WHERE version='012'");
  assert.equal(q.rowCount,1);
  const rls=await pool.query("SELECT relrowsecurity,relforcerowsecurity FROM pg_class WHERE relname='api_pt8_terminal_coverage'");
  assert.equal(rls.rowCount,1);
  assert.equal(rls.rows[0].relrowsecurity,true);
  assert.equal(rls.rows[0].relforcerowsecurity,true);
  assert.equal((await pool.query("SELECT count(*)::int AS n FROM api_pt8_terminal_coverage")).rows[0].n,0);

  const u=randomUUID().slice(0,8);
  const target=await call("POST","/v1/targets",{name:"Phase08 "+u,environment:"SYNTHETIC",baseUrl:"https://pt8-"+u+".fixture.invalid"});
  assert.equal(target.statusCode,201,target.body);
  const tid=target.json().id as string;
  const imported=await call("POST","/v2/targets/"+tid+"/specifications/imports",
   {filename:"phase07-security.openapi.json",content:source},{key:"pt8-import-"+randomUUID()});
  assert.equal(imported.statusCode,201,imported.body);
  const spec=imported.json().specificationId as string;
  const ops=await call("GET","/v2/specifications/"+spec+"/operations?limit=100");
  assert.equal(ops.statusCode,200,ops.body);
  const key=(ops.json() as unknown as {key:string;method:string;path:string}[])
   .find(x=>x.method==="GET"&&x.path==="/pt/account")?.key;
  assert.ok(key);

  async function authorizedScope():Promise<{sid:string;pid:string}>{
   const scope=await call("POST","/v6/pt/targets/"+tid+"/scopes",{
    specificationId:spec,operationKeys:[key],fixtureId:"pt-security-v1",exclusions:[],
    maxEvaluations:2,ratePerMinute:2,maxConcurrency:1,deadlineMs:30000,validityMinutes:15
   },{key:"pt8-scope-"+randomUUID()});
   assert.equal(scope.statusCode,201,scope.body);
   const sid=scope.json().id as string;
   assert.equal((await call("POST","/v6/pt/scopes/"+sid+"/request-authorization",{})).statusCode,201);
   const denied=await call("POST","/v6/pt/test-authority/scopes/"+sid+"/issue",{});
   assert.equal(denied.statusCode,403);
   const permit=await call("POST","/v6/pt/test-authority/scopes/"+sid+"/issue",{}, {authority:true});
   assert.equal(permit.statusCode,201,permit.body);
   return {sid,pid:permit.json().id as string};
  }
  async function start(sid:string):Promise<string>{
   const job=await call("POST","/v7/pt/scopes/"+sid+"/detections",
    {profile:"MISSING_AUTH_ENFORCEMENT",ruleIds:["PT-AUTH-ANONYMOUS"]},
    {key:"pt8-job-"+randomUUID()});
   assert.equal(job.statusCode,201,job.body);
   return job.json().id as string;
  }
  async function terminal(jid:string,status:string,ruleStatus:string,executed:number,notRun:number):Promise<void>{
   const detail=await call("GET","/v7/pt/jobs/"+jid);
   assert.equal(detail.json().status,status,detail.body);
   const summary=await call("GET","/v8/pt/jobs/"+jid+"/terminal-coverage");
   assert.equal(summary.statusCode,200,summary.body);
   const coverage=summary.json() as unknown as {
    status:string;assessmentComplete:boolean;verifiedFixed:boolean;
    rules:{status:string}[];totals:{executedEvaluations:number;notRunEvaluations:number}};
   assert.equal(coverage.status,status);
   assert.equal(coverage.assessmentComplete,false);
   assert.equal(coverage.verifiedFixed,false);
   assert.equal(coverage.rules[0]?.status,ruleStatus);
   assert.equal(coverage.totals.executedEvaluations,executed);
   assert.equal(coverage.totals.notRunEvaluations,notRun);
   assert.equal((await call("GET","/v7/pt/jobs/"+jid+"/report")).statusCode,409);
   assert.equal((await call("GET","/v8/pt/jobs/"+jid+"/terminal-coverage",undefined,{token:"local-test-token-beta"})).statusCode,404);
   const stored=await withTenant(A,tx=>tx.query("SELECT fingerprint,projection FROM api_pt8_terminal_coverage WHERE assessment_id=$1",[jid]));
   assert.equal(stored.rowCount,1);
   assert.match(stored.rows[0].fingerprint,/^[0-9a-f]{64}$/);
  }

  // Queued cancellation creates immutable NOT_RUN coverage without any evaluation.
  const cancelled=await authorizedScope(),cancelId=await start(cancelled.sid);
  assert.equal((await call("POST","/v6/pt/jobs/"+cancelId+"/cancel",{})).statusCode,200);
  await terminal(cancelId,"CANCELLED","NOT_RUN",0,2);
  assert.equal((await withTenant(A,tx=>tx.query("SELECT count(*)::int AS n FROM api_pt_detection_evaluations WHERE assessment_id=$1",[cancelId]))).rows[0].n,0);

  // Revocation after admission fails closed through the real worker.
  const revoked=await authorizedScope(),revId=await start(revoked.sid);
  assert.equal((await call("POST","/v6/pt/test-authority/permits/"+revoked.pid+"/revoke",{}, {authority:true})).statusCode,200);
  assert.equal(await processOneJob(),true);
  await terminal(revId,"FAILED","BLOCKED",0,2);

  // Deterministically fault-inject after one actually governed fixture evaluation.
  const interrupted=await authorizedScope(),faultId=await start(interrupted.sid);
  const claim=await claimJob();
  assert.ok(claim);
  assert.equal(claim.assessment_id,faultId,"one private queue claim must own this test job");
  await withWorkerTenant(A,tx=>tx.query("UPDATE api_assessments SET status='PROCESSING' WHERE id=$1 AND status='QUEUED'",[faultId]));
  await processPtDetectionJob(A,faultId,claim.claim_token,{
   afterEvaluation:async count=>{if(count===1)throw new Error("ISOLATED_PT8_FAULT_AFTER_FIRST_EVALUATION");}
  });
  await terminal(faultId,"FAILED","INCONCLUSIVE",1,1);
  const reserved=await withWorkerTenant(A,tx=>tx.query(
   "SELECT count(*)::int AS n FROM api_pt_detection_evaluations WHERE assessment_id=$1 AND state='RESERVED'",[faultId]));
  assert.equal(reserved.rows[0].n,0);
  await assert.rejects(()=>withTenant(A,tx=>tx.query(
   "UPDATE api_pt8_terminal_coverage SET projection='{}'::jsonb WHERE assessment_id=$1",[faultId])),
   /permission denied|immutable/i);

  // Full customer API product projections are backed by the real PostgreSQL worker.
  const product=await call("GET","/v8/pt/product");
  assert.equal(product.statusCode,200,product.body);
  assert.equal(product.json().productionHost,"BLOCKED");
  const preview=await call("POST","/v8/pt/specifications/"+spec+"/plan-preview",{
   profile:"MISSING_AUTH_ENFORCEMENT",ruleIds:["PT-AUTH-ANONYMOUS"],exclusions:[]
  });
  assert.equal(preview.statusCode,200,preview.body);
  assert.equal(preview.json().plannedEvaluations,2);
  assert.equal(preview.json().executable,true);
  // Explicit operator exclusions are SKIPPED, never PASS and never silently executable.
  const excludedPreview=await call("POST","/v8/pt/specifications/"+spec+"/plan-preview",{
   profile:"MISSING_AUTH_ENFORCEMENT",ruleIds:["PT-AUTH-ANONYMOUS"],exclusions:["/pt/account"]
  });
  assert.equal(excludedPreview.statusCode,200,excludedPreview.body);
  assert.equal(excludedPreview.json().executable,false);
  assert.equal(excludedPreview.json().applicableEvaluations,0);
  const excludedRule=(excludedPreview.json() as unknown as {rules:{status:string;reason:string}[]}).rules[0];
  assert.equal(excludedRule?.status,"SKIPPED");
  assert.equal(excludedRule?.reason,"OPERATION_EXCLUDED");
  const forbiddenPreview=await call("POST","/v8/pt/specifications/"+spec+"/plan-preview",{
   profile:"MISSING_AUTH_ENFORCEMENT",ruleIds:["PT-AUTH-ANONYMOUS"],verdict:"SAFE"
  });
  assert.equal(forbiddenPreview.statusCode,400);
  const complete=await authorizedScope(),doneId=await start(complete.sid);
  assert.equal(await processOneJob(),true);
  const completed=await call("GET","/v7/pt/jobs/"+doneId);
  assert.equal(completed.json().status,"COMPLETED",completed.body);
  const progress=await call("GET","/v8/pt/jobs/"+doneId+"/progress");
  assert.equal(progress.statusCode,200,progress.body);
  assert.equal(progress.json().executedEvaluations,2);
  assert.equal(progress.json().notYetExecuted,0);
  const findings=await call("GET","/v8/pt/findings?targetId="+tid+"&ruleId=PT-AUTH-ANONYMOUS&limit=10");
  assert.equal(findings.statusCode,200,findings.body);
  const rows=(findings.json() as unknown as {items:{id:string;rule_id:string}[]}).items;
  assert.equal(rows.length,1);
  assert.equal(rows[0]?.rule_id,"PT-AUTH-ANONYMOUS");
  const single=await call("GET","/v8/pt/findings/"+rows[0]!.id);
  assert.equal(single.statusCode,200,single.body);
  assert.equal(single.json().verifiedFixed,false);
  assert.equal(single.json().runtimeCustomerVerification,false);
  assert.equal((await call("GET","/v8/pt/findings/"+rows[0]!.id,undefined,{token:"local-test-token-beta"})).statusCode,404);
  const history=await call("GET","/v8/pt/history?targetId="+tid+"&limit=20");
  assert.equal(history.statusCode,200,history.body);
  const runs=(history.json() as unknown as {items:{id:string;status:string}[]}).items;
  assert.ok(runs.some(x=>x.id===doneId&&x.status==="COMPLETED"));
  assert.ok(runs.some(x=>x.id===faultId&&x.status==="FAILED"));
  assert.equal((await call("GET","/v8/pt/history?targetId="+tid,undefined,{token:"local-test-token-beta"})).statusCode,200);
  assert.equal(((await call("GET","/v8/pt/history?targetId="+tid,undefined,{token:"local-test-token-beta"})).json() as unknown as {items:unknown[]}).items.length,0);

 }finally{await app.close();await closeDatabase();}
});
