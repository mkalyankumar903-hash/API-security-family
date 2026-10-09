import {test} from "node:test";
import assert from "node:assert/strict";
import {randomUUID} from "node:crypto";
import {migrate,claimJob,withTenant,withWorkerTenant,closeDatabase} from "../packages/database/src/index.js";
import {makeApp} from "../packages/service/src/app.js";
import {scheduleConservativeRetry,classifyWorkerFailure} from "../packages/worker/src/safety-retry.js";

const A="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const source=JSON.stringify({openapi:"3.1.0",info:{title:"Retry fixture",version:"1.0.0"},
 paths:{"/health":{get:{responses:{"200":{description:"Response"}}}}}});

test("Phase10 real PG: bounded, idempotent pre-evaluation retry and terminal quarantine",async()=>{
 await migrate();const app=await makeApp();
 const req=async(method:"POST"|"GET",url:string,body?:object,key?:string)=>
  app.inject({method,url,payload:body,headers:{authorization:"Bearer local-test-token-alpha",
   ...(key?{"idempotency-key":key}:{})}});
 try{
  const unique=randomUUID().slice(0,8);
  const t=await req("POST","/v1/targets",{name:"Retry "+unique,
   baseUrl:"https://retry-"+unique+".fixture.invalid",environment:"SYNTHETIC"});
  assert.equal(t.statusCode,201,t.body);
  const tid=t.json().id as string;
  const s=await req("POST","/v1/targets/"+tid+"/specifications",{filename:"phase10-retry.json",content:source});
  assert.equal(s.statusCode,201,s.body);
  const id=s.json().id as string;
  const job=await req("POST","/v1/targets/"+tid+"/assessments",
   {mode:"SPEC_ONLY",specificationId:id},"retry-"+randomUUID());
  assert.equal(job.statusCode,201,job.body);
  const jid=job.json().id as string;
  const refusal=classifyWorkerFailure({code:"23505"});
  assert.equal(refusal,"NON_RETRYABLE");
  let lease=await claimJob();
  assert.equal(lease?.assessment_id,jid);
  assert.equal(await scheduleConservativeRetry(lease!,{code:"PERMIT_EXPIRED"}),"NOT_RETRYABLE");
  for(let retry=0;retry<3;retry++){
   const outcome=await scheduleConservativeRetry(lease!,{code:"08006"});
   assert.equal(outcome,"RETRY_SCHEDULED");
   const record=await withWorkerTenant(A,tx=>tx.query(
    "SELECT retry_count,claim_token,next_eligible_at FROM api_queue.api_assessment_queue WHERE assessment_id=$1",[jid]));
   assert.equal(record.rows[0].retry_count,retry+1);
   assert.equal(record.rows[0].claim_token,null);
   assert.ok(new Date(record.rows[0].next_eligible_at).getTime()>Date.now());
   // Controlled test clock transition; NEVER alter live permit authority or budget.
   await withWorkerTenant(A,tx=>tx.query(
    "UPDATE api_queue.api_assessment_queue SET next_eligible_at=clock_timestamp()-interval '1 second' WHERE assessment_id=$1",[jid]));
   lease=await claimJob();
   assert.equal(lease?.assessment_id,jid);
   assert.equal(lease?.claim_generation,retry+2);
  }
  assert.equal(await scheduleConservativeRetry(lease!,{code:"08006"}),"RETRY_EXHAUSTED");
  const state=await req("GET","/v1/assessments/"+jid);
  assert.equal(state.json().status,"FAILED");
  assert.equal(state.json().errorCode,"WORKER_RETRY_EXHAUSTED");
  const final=await withTenant(A,async tx=>{
   const quarantine=await tx.query("SELECT reason_code,attempts FROM api_worker_quarantine WHERE assessment_id=$1",[jid]);
   const attempts=await tx.query("SELECT state,failure_code FROM api_worker_attempts WHERE assessment_id=$1 ORDER BY claim_generation",[jid]);
   const events=await tx.query("SELECT kind FROM api_worker_events WHERE assessment_id=$1 ORDER BY occurred_at",[jid]);
   const report=await tx.query("SELECT 1 FROM api_reports WHERE assessment_id=$1",[jid]);
   return {quarantine:quarantine.rows[0],attempts:attempts.rows,events:events.rows,reportCount:report.rowCount};
  });
  assert.deepEqual(final.quarantine,{reason_code:"WORKER_RETRY_EXHAUSTED",attempts:4});
  assert.equal(final.attempts.length,4);
  assert.equal(final.reportCount,0);
  assert.equal(final.events.filter(x=>x.kind==="RETRY_SCHEDULED").length,3);
  assert.equal(final.events.filter(x=>x.kind==="RETRY_EXHAUSTED").length,1);
  const diagnostic=await req("GET","/v10/workers/assessments/"+jid+"/execution");
  assert.equal(diagnostic.statusCode,200,diagnostic.body);
  assert.equal(diagnostic.json().quarantine.reason_code,"WORKER_RETRY_EXHAUSTED");
  assert.equal(diagnostic.json().attempts.length,4);
  assert.equal(diagnostic.json().queue,null);
  assert.equal((await withWorkerTenant(A,tx=>tx.query("SELECT 1 FROM api_queue.api_assessment_queue WHERE assessment_id=$1",[jid]))).rowCount,0);
 }finally{await app.close();await closeDatabase();}
});
