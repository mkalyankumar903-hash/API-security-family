import {test} from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {randomUUID} from "node:crypto";
import {migrate,pool,withTenant,withWorkerTenant,claimJob,closeDatabase} from "../packages/database/src/index.js";
import {makeApp} from "../packages/service/src/app.js";
import {processOneJob} from "../packages/worker/src/index.js";
import {processPtOrchestrationJob} from "../packages/worker/src/pt-orchestrator.js";

const A="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",B="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const AUTH="local-test-token-alpha",SIGNER=process.env.PT_TEST_AUTHORITY_KEY??"";
const source=readFileSync(new URL("../fixtures/phase07-security.openapi.json",import.meta.url),"utf8");
type API={statusCode:number;body:string;json:()=>Record<string,unknown>};
type O={key:string;method:string;path:string};
const RULE_PATHS=["/pt/account","/pt/resources/bob","/pt/admin","/pt/confidential"];
const PROFILE="SYNTHETIC_PT_COMPLETE_SUPPORTED";

test("Phase09 real PostgreSQL: synthetic multi-stage execution, governor, immutability, isolation, cancellation and recovery",async()=>{
 await migrate();const app=await makeApp();
 async function call(method:"GET"|"POST",url:string,data?:unknown,options?:{key?:string;token?:string;authority?:boolean}):Promise<API>{
  return app.inject({method,url,payload:data as object|undefined,headers:{
   authorization:"Bearer "+(options?.token??AUTH),
   ...(options?.key?{"idempotency-key":options.key}:{}),
   ...(options?.authority?{"x-pt-authority-key":SIGNER}:{})
  }});
 }
 const ok=(r:API,code:number)=>assert.equal(r.statusCode,code,r.body);
 try{
  assert.equal((await pool.query("SELECT 1 FROM api_schema_migrations WHERE version='013'")).rowCount,1);
  const rls=await pool.query("SELECT relname,relrowsecurity,relforcerowsecurity FROM pg_class WHERE relname LIKE 'api_pt9_%' AND relkind='r'");
  assert.equal(rls.rowCount,5);
  assert.ok(rls.rows.every(x=>x.relrowsecurity===true&&x.relforcerowsecurity===true));
  for(const table of ["api_pt9_plans","api_pt9_stages","api_pt9_reports","api_pt9_terminal"]){
   const privilege=(await pool.query("SELECT has_table_privilege('api_family',$1,'UPDATE') AS permitted",["public."+table])).rows[0].permitted;
   assert.equal(privilege,false,table+" customer UPDATE must be denied");
  }
  const suffix=randomUUID().slice(0,8);
  const target=await call("POST","/v1/targets",{name:"Phase09 "+suffix,environment:"SYNTHETIC",
   baseUrl:"https://phase09-"+suffix+".fixture.invalid"});ok(target,201);
  const tid=target.json().id as string;
  const imported=await call("POST","/v2/targets/"+tid+"/specifications/imports",
   {filename:"phase07-security.openapi.json",content:source},{key:"pt9-import-"+randomUUID()});ok(imported,201);
  const specId=imported.json().specificationId as string;
  const ops=await call("GET","/v2/specifications/"+specId+"/operations?limit=100");ok(ops,200);
  const normalized=ops.json() as unknown as O[];
  const operationKeys=RULE_PATHS.map(path=>{
   const key=normalized.find(x=>x.method==="GET"&&x.path===path)?.key;
   assert.ok(key,"missing trusted fixture operation "+path);return key;
  });
  async function scope(policyBudget=14):Promise<{sid:string;pid:string}>{
   const created=await call("POST","/v6/pt/targets/"+tid+"/scopes",{
    specificationId:specId,operationKeys,fixtureId:"pt-security-v1",exclusions:[],
    maxEvaluations:policyBudget,ratePerMinute:policyBudget,
    maxConcurrency:1,deadlineMs:30000,validityMinutes:15
   },{key:"pt9-scope-"+randomUUID()});ok(created,201);
   const sid=created.json().id as string;
   ok(await call("POST","/v6/pt/scopes/"+sid+"/request-authorization",{}),201);
   const signing=await call("POST","/v6/pt/test-authority/scopes/"+sid+"/issue",{}, {authority:true});ok(signing,201);
   return {sid,pid:signing.json().id as string};
  }
  function previewPath(sid:string,policy=PROFILE,profile="SECURE_BASELINE"){
   return "/v9/pt/scopes/"+sid+"/preview?"+new URLSearchParams({policyId:policy,profile});
  }
  async function start(sid:string,profile="SECURE_BASELINE",key="pt9-job-"+randomUUID(),policy=PROFILE){
   return call("POST","/v9/pt/scopes/"+sid+"/orchestrations",{policyId:policy,profile},{key});
  }
  const policies=await call("GET","/v9/pt/policies");ok(policies,200);
  assert.equal((policies.json().profiles as unknown[]).length,4);
  const missingPermit=await call("POST","/v6/pt/targets/"+tid+"/scopes",{
   specificationId:specId,operationKeys,fixtureId:"pt-security-v1",exclusions:[],
   maxEvaluations:14,ratePerMinute:14,maxConcurrency:1,deadlineMs:30000,validityMinutes:15
  },{key:"pt9-unsigned-"+randomUUID()});ok(missingPermit,201);
  const unsignedId=missingPermit.json().id as string;
  const unsignedPreview=await call("GET",previewPath(unsignedId));ok(unsignedPreview,200);
  assert.equal(unsignedPreview.json().authorizationReady,false);
  assert.equal(unsignedPreview.json().denialCode,"AUTHORIZATION_MISSING");
  ok(await start(unsignedId),409);
  assert.equal((await withWorkerTenant(A,tx=>tx.query("SELECT count(*)::int AS n FROM api_pt9_plans"))).rows[0].n,0);

  const {sid,pid}=await scope();
  const firstPreview=await call("GET",previewPath(sid));ok(firstPreview,200);
  const secondPreview=await call("GET",previewPath(sid));ok(secondPreview,200);
  assert.equal(firstPreview.json().planFingerprint,secondPreview.json().planFingerprint);
  assert.equal((firstPreview.json().plan as {evaluations:unknown[]}).evaluations.length,14);
  assert.deepEqual((firstPreview.json().plan as {stages:{id:string}[]}).stages.map(x=>x.id),
   ["preflight","authentication","authorization","response","reconciliation","finalization"]);
  const denyBody=await call("POST","/v9/pt/scopes/"+sid+"/orchestrations",
   {policyId:PROFILE,profile:"SECURE_BASELINE",authorized:true},{key:"pt9-invalid-"+randomUUID()});ok(denyBody,400);
  const sameKey="pt9-concurrent-"+randomUUID();
  const duplicates=await Promise.all([start(sid,"SECURE_BASELINE",sameKey),start(sid,"SECURE_BASELINE",sameKey)]);
  assert.deepEqual(duplicates.map(x=>x.statusCode).sort(),[200,201]);
  const jid=duplicates[0]!.json().id as string;
  assert.equal(duplicates[1]!.json().id,jid);
  assert.equal((await call("GET","/v9/pt/orchestrations/"+jid,undefined,{token:"local-test-token-beta"})).statusCode,404);
  assert.equal((await call("GET","/v9/pt/orchestrations/"+jid)).json().status,"QUEUED");
  assert.equal(await processOneJob(),true);
  const completed=await call("GET","/v9/pt/orchestrations/"+jid);ok(completed,200);
  assert.equal(completed.json().status,"COMPLETED",completed.body);
  const stages=completed.json().stages as {stage_id:string;status:string;evidence_fingerprint:string}[];
  assert.equal(stages.length,6);
  assert.ok(stages.every(x=>x.status==="COMPLETED"&&/^[0-9a-f]{64}$/.test(x.evidence_fingerprint)));
  assert.equal((completed.json().accounting as Record<string,number>).CONSUMED,14);
  const signed=await withTenant(A,tx=>tx.query("SELECT consumed,reserved FROM api_pt_permits WHERE id=$1",[pid]));
  assert.equal(signed.rows[0].consumed,14);assert.equal(signed.rows[0].reserved,0);
  const successes=await call("GET","/v9/pt/orchestrations/"+jid+"/report");ok(successes,200);
  const report=successes.json();
  assert.equal(report.syntheticOnly,true);assert.equal(report.customerNetworkRequests,0);
  assert.equal(report.verifiedFixed,false);assert.equal(report.customerRuntimeVerified,false);
  assert.deepEqual(report.observations,[]);
  assert.equal((report.accounting as {executed:number}).executed,14);
  assert.equal((report.ruleResults as unknown[]).length,8);
  ok(await call("GET","/v9/pt/orchestrations/"+jid+"/export"),200);
  assert.equal((await call("GET","/v9/pt/orchestrations/"+jid+"/report",undefined,{token:"local-test-token-beta"})).statusCode,409);
  await assert.rejects(()=>withTenant(A,tx=>tx.query("UPDATE api_pt9_plans SET fingerprint=$1 WHERE assessment_id=$2",["a".repeat(64),jid])),
   /permission denied|immutable/i);
  const isolated=await withTenant(B,tx=>tx.query("SELECT * FROM api_pt9_stages WHERE assessment_id=$1",[jid]));
  assert.equal(isolated.rowCount,0);
  const history=await call("GET","/v9/pt/targets/"+tid+"/history?limit=20");ok(history,200);
  assert.ok((history.json() as unknown as {id:string}[]).some(x=>x.id===jid));
  assert.equal((await call("GET","/v9/pt/targets/"+tid+"/history",undefined,{token:"local-test-token-beta"})).json() instanceof Array,true);

  const vulnerable=await scope();
  const observed=await start(vulnerable.sid,"MISSING_AUTH_ENFORCEMENT");ok(observed,201);
  const positiveId=observed.json().id as string;
  assert.equal(await processOneJob(),true);
  const vulnReport=await call("GET","/v9/pt/orchestrations/"+positiveId+"/report");ok(vulnReport,200);
  assert.ok((vulnReport.json().observations as unknown[]).length>0);
  assert.equal((await call("GET","/v9/pt/orchestrations/"+positiveId+"/compare/"+jid)).json().compatibility,"INCOMPATIBLE");
  assert.equal((await call("GET","/v9/pt/orchestrations/"+positiveId+"/report",undefined,{token:"local-test-token-beta"})).statusCode,409);

  const revoked=await scope(4);
  const deniedStart=await start(revoked.sid,"SECURE_BASELINE","pt9-focused-"+randomUUID(),"SYNTHETIC_PT_AUTHORIZATION_FOCUSED");ok(deniedStart,201);
  const revokedId=deniedStart.json().id as string;
  ok(await call("POST","/v6/pt/test-authority/permits/"+revoked.pid+"/revoke",{}, {authority:true}),200);
  assert.equal(await processOneJob(),true);
  const revokedInfo=await call("GET","/v9/pt/orchestrations/"+revokedId);ok(revokedInfo,200);
  assert.equal(revokedInfo.json().status,"FAILED");
  const revokedTerminal=await call("GET","/v9/pt/orchestrations/"+revokedId+"/terminal");ok(revokedTerminal,200);
  assert.equal(revokedTerminal.json().assessmentComplete,false);
  assert.equal((await call("GET","/v9/pt/orchestrations/"+revokedId+"/report")).statusCode,409);
  const cancelled=await scope(4);
  const cancelRun=await start(cancelled.sid,"SECURE_BASELINE","pt9-cancel-"+randomUUID(),"SYNTHETIC_PT_AUTHORIZATION_FOCUSED");ok(cancelRun,201);
  const cancelledId=cancelRun.json().id as string;
  ok(await call("POST","/v9/pt/orchestrations/"+cancelledId+"/cancel",{}),200);
  const cancellation=await call("GET","/v9/pt/orchestrations/"+cancelledId+"/terminal");ok(cancellation,200);
  assert.equal(cancellation.json().status,"CANCELLED");
  assert.equal((await call("GET","/v9/pt/orchestrations/"+cancelledId+"/report")).statusCode,409);

  const recovery=await scope(4);
  const run=await start(recovery.sid,"SECURE_BASELINE","pt9-recover-"+randomUUID(),"SYNTHETIC_PT_AUTHORIZATION_FOCUSED");ok(run,201);
  const rid=run.json().id as string;
  const firstClaim=await claimJob();assert.ok(firstClaim);
  assert.equal(firstClaim.assessment_id,rid);
  await withWorkerTenant(A,tx=>tx.query("UPDATE api_assessments SET status='PROCESSING' WHERE id=$1 AND status='QUEUED'",[rid]));
  await processPtOrchestrationJob(A,rid,firstClaim.claim_token,{afterCheckpoint:async stageId=>{
   if(stageId==="preflight")throw new Error("PT9_ISOLATED_PROCESS_EXIT");
  }});
  const persisted=await withTenant(A,tx=>tx.query("SELECT status FROM api_pt9_stages WHERE assessment_id=$1 AND stage_id='preflight'",[rid]));
  assert.equal(persisted.rows[0].status,"COMPLETED");
  assert.equal((await call("GET","/v9/pt/orchestrations/"+rid)).json().status,"PROCESSING");
  await withWorkerTenant(A,tx=>tx.query("UPDATE api_queue.api_assessment_queue SET locked_until=now()-interval '1 second' WHERE assessment_id=$1",[rid]));
  const secondClaim=await claimJob();assert.ok(secondClaim);
  assert.equal(secondClaim.assessment_id,rid);
  assert.notEqual(secondClaim.claim_token,firstClaim.claim_token);
  await processPtOrchestrationJob(A,rid,secondClaim.claim_token);
  assert.equal((await call("GET","/v9/pt/orchestrations/"+rid)).json().status,"COMPLETED");
  const stageAudit=await withTenant(A,tx=>tx.query("SELECT code,count(*)::int AS n FROM api_pt9_decisions WHERE assessment_id=$1 AND stage_id='preflight' GROUP BY code",[rid]));
  assert.equal(stageAudit.rows.find(x=>x.code==="STAGE_ADMITTED")?.n,1);
  assert.equal((await withTenant(A,tx=>tx.query("SELECT consumed,reserved FROM api_pt_permits WHERE id=$1",[recovery.pid]))).rows[0].consumed,4);
  assert.equal((await withTenant(A,tx=>tx.query("SELECT count(*)::int AS n FROM api_pt_detection_evaluations WHERE assessment_id=$1",[rid]))).rows[0].n,4);

 }finally{await app.close();await closeDatabase();}
});
