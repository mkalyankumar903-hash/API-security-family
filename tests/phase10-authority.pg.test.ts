import {test} from "node:test";
import assert from "node:assert/strict";
import {randomUUID} from "node:crypto";
import {readFileSync} from "node:fs";
import {migrate,claimJob,renewWorkerClaim,withTenant,withWorkerTenant,closeDatabase} from "../packages/database/src/index.js";
import {scheduleConservativeRetry} from "../packages/worker/src/safety-retry.js";
import {processPtOrchestrationJob} from "../packages/worker/src/pt-orchestrator.js";
import {makeApp} from "../packages/service/src/app.js";

const A="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const FIXTURE=readFileSync(new URL("../fixtures/phase07-security.openapi.json",import.meta.url),"utf8");
const PATHS=["/pt/account","/pt/resources/bob","/pt/admin","/pt/confidential"];
test("Phase10 authority: renewal versus revocation, cancellation, emergency stop and expired deadline, no silent budget refunds",async()=>{
 await migrate();const app=await makeApp();
 const api=(method:"GET"|"POST",url:string,data?:object,key?:string,signer=false)=>
  app.inject({method,url,payload:data,headers:{
   authorization:"Bearer local-test-token-alpha",
   ...(key?{"idempotency-key":key}:{}),
   ...(signer?{"x-pt-authority-key":process.env.PT_TEST_AUTHORITY_KEY??""}:{})}});
 const accepted=async(method:"GET"|"POST",url:string,data?:object,key?:string,signer=false)=>{
  const r=await api(method,url,data,key,signer);assert.equal(r.statusCode,method==="GET"?200:201,r.body);return r.json();
 };
 try{
  const target=await accepted("POST","/v1/targets",{name:"Authority "+randomUUID().slice(0,8),
   baseUrl:"https://authority-"+randomUUID()+".fixture.invalid",environment:"SYNTHETIC"});
  const tid=target.id as string;
  const imported=await accepted("POST","/v2/targets/"+tid+"/specifications/imports",
   {filename:"phase07-security.openapi.json",content:FIXTURE},"authority-import-"+randomUUID());
  const specId=imported.specificationId as string;
  const ops=await accepted("GET","/v2/specifications/"+specId+"/operations?limit=100") as unknown as
   {method:string;path:string;key:string}[];
  const keys=PATHS.map(path=>{
   const key=ops.find(x=>x.method==="GET"&&x.path===path)?.key;assert.ok(key);return key;
  });
  const start=async()=>{
   const scope=await accepted("POST","/v6/pt/targets/"+tid+"/scopes",{
    specificationId:specId,operationKeys:keys,fixtureId:"pt-security-v1",exclusions:[],
    maxEvaluations:4,ratePerMinute:4,maxConcurrency:1,deadlineMs:30000,validityMinutes:15
   },"authority-scope-"+randomUUID());
   const sid=scope.id as string;
   await accepted("POST","/v6/pt/scopes/"+sid+"/request-authorization",{});
   const permit=await accepted("POST","/v6/pt/test-authority/scopes/"+sid+"/issue",{},undefined,true);
   const job=await accepted("POST","/v9/pt/scopes/"+sid+"/orchestrations",{
    policyId:"SYNTHETIC_PT_AUTHORIZATION_FOCUSED",profile:"SECURE_BASELINE"
   },"authority-job-"+randomUUID());
   const claim=await claimJob();
   assert.equal(claim?.assessment_id,job.id);
   return {jobId:job.id as string,permitId:permit.id as string,claim:claim!};
  };
  // Trusted revocation invalidates ongoing heartbeats, any future governed stage,
  // and transient retry eligibility. It must not turn a queue claim into a permit.
  const revoked=await start();
  const revoke=await api("POST","/v6/pt/test-authority/permits/"+revoked.permitId+"/revoke",{},undefined,true);
  assert.equal(revoke.statusCode,200,revoke.body);
  assert.equal(await renewWorkerClaim(revoked.claim),false);
  assert.equal(await scheduleConservativeRetry(revoked.claim,{code:"08006"}),"NOT_RETRYABLE");
  await processPtOrchestrationJob(A,revoked.jobId,revoked.claim.claim_token);
  const revokedResult=await api("GET","/v9/pt/orchestrations/"+revoked.jobId);
  assert.equal(revokedResult.json().status,"FAILED");
  assert.equal((await api("GET","/v9/pt/orchestrations/"+revoked.jobId+"/report")).statusCode,409);
  const revokedBudget=await withTenant(A,tx=>tx.query("SELECT consumed,reserved FROM api_pt_permits WHERE id=$1",[revoked.permitId]));
  assert.equal(revokedBudget.rows[0].consumed,0);assert.equal(revokedBudget.rows[0].reserved,0);

  // Cancellation is a terminal authority: even if lease still existed at the
  // beginning of the race, a subsequent renewal and completion cannot succeed.
  const cancelled=await start();
  const cancel=await api("POST","/v9/pt/orchestrations/"+cancelled.jobId+"/cancel",{});
  assert.equal(cancel.statusCode,200,cancel.body);
  assert.equal(await renewWorkerClaim(cancelled.claim),false);
  await processPtOrchestrationJob(A,cancelled.jobId,cancelled.claim.claim_token);
  assert.equal((await api("GET","/v9/pt/orchestrations/"+cancelled.jobId)).json().status,"CANCELLED");
  assert.equal((await api("GET","/v9/pt/orchestrations/"+cancelled.jobId+"/report")).statusCode,409);
  assert.equal((await api("GET","/v9/pt/orchestrations/"+cancelled.jobId+"/terminal")).statusCode,200);

  // Deadline belongs to Phase06 job authority and cannot be extended by Phase10.
  const deadline=await start();
  await withWorkerTenant(A,tx=>tx.query(
   "UPDATE api_pt_jobs SET job_deadline=clock_timestamp()-interval '1 second' WHERE assessment_id=$1",[deadline.jobId]));
  assert.equal(await renewWorkerClaim(deadline.claim),false);
  assert.equal(await scheduleConservativeRetry(deadline.claim,{code:"08006"}),"NOT_RETRYABLE");
  await processPtOrchestrationJob(A,deadline.jobId,deadline.claim.claim_token);
  assert.equal((await api("GET","/v9/pt/orchestrations/"+deadline.jobId)).json().status,"FAILED");
  assert.equal((await api("GET","/v9/pt/orchestrations/"+deadline.jobId+"/report")).statusCode,409);

  const stopped=await start();
  const stop=await api("POST","/v6/pt/test-authority/stop",{},undefined,true);
  assert.equal(stop.statusCode,200,stop.body);
  assert.equal(await renewWorkerClaim(stopped.claim),false);
  assert.equal(await scheduleConservativeRetry(stopped.claim,{code:"08006"}),"NOT_RETRYABLE",
   "trusted stop is checked before accepting a private retry lease");
  await processPtOrchestrationJob(A,stopped.jobId,stopped.claim.claim_token);
  assert.equal((await api("GET","/v9/pt/orchestrations/"+stopped.jobId)).json().status,"CANCELLED");
  assert.equal((await api("GET","/v9/pt/orchestrations/"+stopped.jobId+"/report")).statusCode,409);
  const permitAudit=await withTenant(A,tx=>tx.query("SELECT count(*)::int AS n FROM api_pt_permits WHERE consumed<0 OR reserved<0"));
  assert.equal(permitAudit.rows[0].n,0);
 }finally{
  // Trusted synthetic stop is test-only; never leave the test tenant globally disabled.
  await api("POST","/v6/pt/test-authority/resume",{},undefined,true).catch(()=>null);
  await app.close();await closeDatabase();
 }
});
