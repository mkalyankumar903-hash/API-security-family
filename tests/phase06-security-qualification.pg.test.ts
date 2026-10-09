import {test} from "node:test";
import assert from "node:assert/strict";
import {randomUUID} from "node:crypto";
import {readFileSync} from "node:fs";
import {Pool} from "pg";
import {makeApp} from "../packages/service/src/app.js";
import {migrate,pool,workerPool,claimJob,withTenant,withWorkerTenant} from "../packages/database/src/index.js";
import {processOneJob} from "../packages/worker/src/index.js";
import {processPtJob} from "../packages/worker/src/pt.js";

const TENANT="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const AUTHORITY=process.env.PT_TEST_AUTHORITY_KEY??"";
const spec=readFileSync(new URL("../fixtures/phase2-openapi30-v1.json",import.meta.url),"utf8");
function barrier(){
 let reached!:()=>void,release!:()=>void;
 const entered=new Promise<void>(r=>reached=r);
 const wait=new Promise<void>(r=>release=r);
 return {entered,release:()=>release(),block:async()=>{reached();await wait;}};
}
test("Phase06 hardening: real competing PostgreSQL security boundaries",async t=>{
 await migrate();
 const app=await makeApp();
 const inspector=new Pool({connectionString:process.env.MIGRATION_DATABASE_URL,max:1});
 const call=async(method:"GET"|"POST",url:string,payload?:unknown,key?:string,authority=false)=>
  app.inject({method,url,headers:{authorization:"Bearer local-test-token-alpha",
   ...(key?{"idempotency-key":key}:{}),...(authority?{"x-pt-authority-key":AUTHORITY}:{})},payload:payload as object|undefined});
 async function prepare(budget=2,concurrency=2,rate=2){
  const suffix=randomUUID().slice(0,8);
  const target=await call("POST","/v1/targets",{name:"PT-Qualification-"+suffix,baseUrl:"https://pt-qualification-"+suffix+".fixture.invalid",environment:"SYNTHETIC"});
  assert.equal(target.statusCode,201,target.body);
  const targetId=target.json().id as string;
  const upload=await call("POST","/v2/targets/"+targetId+"/specifications/imports",
   {filename:"phase2-openapi30-v1.json",content:spec},"qualification-import-"+randomUUID());
  assert.equal(upload.statusCode,201,upload.body);
  const specificationId=upload.json().specificationId as string;
  const operations=await call("GET","/v2/specifications/"+specificationId+"/operations?limit=100");
  const op=(operations.json() as {key:string;method:string;path:string}[])
   .find(x=>x.method==="GET"&&x.path==="/status");
  assert.ok(op);
  const keys=[op.key];
  const proposed=await call("POST","/v6/pt/targets/"+targetId+"/scopes",
   {specificationId,operationKeys:keys,exclusions:[],maxEvaluations:budget,maxConcurrency:concurrency,
    ratePerMinute:rate,deadlineMs:30000,validityMinutes:10,fixtureId:"billing-safe-v1"},
   "qualification-scope-"+randomUUID());
  assert.equal(proposed.statusCode,201,proposed.body);
  const scopeId=proposed.json().id as string;
  const requested=await call("POST","/v6/pt/scopes/"+scopeId+"/request-authorization");
  assert.equal(requested.statusCode,201,requested.body);
  const issued=await call("POST","/v6/pt/test-authority/scopes/"+scopeId+"/issue",{},undefined,true);
  assert.equal(issued.statusCode,201,issued.body);
  return {targetId,scopeId,keys,permitId:issued.json().id as string};
 }
 async function queue(scopeId:string,keys:string[]){
  const response=await call("POST","/v6/pt/scopes/"+scopeId+"/jobs",{operationKeys:keys},"qualification-job-"+randomUUID());
  assert.equal(response.statusCode,201,response.body);
  return response.json().id as string;
 }
 async function startManually(jobId:string){
  const claimed=await claimJob();
  assert.equal(claimed?.assessment_id,jobId);
  await withWorkerTenant(TENANT,tx=>tx.query("UPDATE api_assessments SET status='PROCESSING' WHERE id=$1 AND status='QUEUED'",[jobId]));
  return claimed!.claim_token;
 }
 async function snapshot(jobId:string,permitId:string){
  const a=await withTenant(TENANT,tx=>tx.query("SELECT status,error_code FROM api_assessments WHERE id=$1",[jobId]));
  const p=await withTenant(TENANT,tx=>tx.query("SELECT consumed,reserved,rate_used,revoked_at FROM api_pt_permits WHERE id=$1",[permitId]));
  const l=await withTenant(TENANT,tx=>tx.query("SELECT operation_key,state FROM api_pt_ledger WHERE assessment_id=$1",[jobId]));
  const r=await withTenant(TENANT,tx=>tx.query("SELECT decision,code FROM api_pt_receipts WHERE assessment_id=$1",[jobId]));
  const report=await withTenant(TENANT,tx=>tx.query("SELECT count(*)::int AS n FROM api_pt_reports WHERE assessment_id=$1",[jobId]));
  return {job:a.rows[0],permit:p.rows[0],ledger:l.rows,receipts:r.rows,reports:report.rows[0].n as number};
 }
 async function blockedBy(pid:number){
  // State-observed synchronization, NOT a sleep-based assumption about races.
  for(let attempt=0;attempt<180;attempt++){
   const q=await inspector.query("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1::integer=ANY(pg_blocking_pids(pid))) AS seen",[pid]);
   if(q.rows[0].seen)return;
   await new Promise(r=>setTimeout(r,20));
  }
  throw new Error("EXPECTED_POSTGRES_LOCK_CONTENTION_NOT_OBSERVED");
 }
 try{
  await t.test("two workers rate-consume simultaneously; PG permit row lock grants exactly one slot", {timeout:25000},async()=>{
   const s=await prepare(3,2,1),a=await queue(s.scopeId,s.keys),b=await queue(s.scopeId,s.keys);
   const hold=barrier();let announce!:(pid:number)=>void;
   const ready=new Promise<number>(r=>announce=r);
   const tx=withTenant(TENANT,async conn=>{
    const pid=Number((await conn.query("SELECT pg_backend_pid() AS pid")).rows[0].pid);
    await conn.query("SELECT id FROM api_pt_permits WHERE id=$1 FOR UPDATE",[s.permitId]);
    announce(pid);await hold.block();
   });
   const pid=await ready;
   const workers=Promise.all([processOneJob(),processOneJob()]);
   try{await blockedBy(pid);}finally{hold.release();await tx;}
   assert.deepEqual(await workers,[true,true]);
   const aa=await snapshot(a,s.permitId),bb=await snapshot(b,s.permitId);
   const decisions=[...aa.receipts,...bb.receipts];
   assert.equal(decisions.filter(x=>x.decision==="ALLOWED").length,1);
   assert.equal(decisions.filter(x=>x.code==="RATE_LIMIT").length,1);
   assert.deepEqual([aa.permit.consumed,aa.permit.reserved,aa.permit.rate_used],[1,0,1]);
   assert.equal(aa.reports+bb.reports,2);
   assert.equal([aa.job.status,bb.job.status].filter(x=>x==="COMPLETED").length,1);
  });
  await t.test("revocation commits while worker blocked before admission; no fixture allowed", {timeout:25000},async()=>{
   const s=await prepare(),id=await queue(s.scopeId,s.keys);
   const hold=barrier();let announce!:(pid:number)=>void;
   const ready=new Promise<number>(r=>announce=r);
   const tx=withTenant(TENANT,async conn=>{
    const pid=Number((await conn.query("SELECT pg_backend_pid() AS pid")).rows[0].pid);
    await conn.query("SELECT enabled FROM api_pt_stop WHERE tenant_id=$1 FOR UPDATE",[TENANT]);
    announce(pid);await hold.block();
    await conn.query("UPDATE api_pt_permits SET revoked_at=now() WHERE id=$1",[s.permitId]);
   });
   const pid=await ready,worker=processOneJob();
   try{await blockedBy(pid);}finally{hold.release();await tx;}
   assert.equal(await worker,true);
   const state=await snapshot(id,s.permitId);
   assert.equal(state.job.status,"FAILED");
   assert.ok(state.receipts.every(x=>x.decision!=="ALLOWED"));
   assert.deepEqual([state.permit.consumed,state.permit.reserved],[0,0]);
   assert.equal(state.reports,1);
  });
  await t.test("real revoke endpoint races with already RESERVED operation", {timeout:25000},async()=>{
   const s=await prepare(1),id=await queue(s.scopeId,s.keys),claim=await startManually(id);
   const gate=barrier();
   const worker=processPtJob(TENANT,id,claim,{afterReservation:gate.block});
   await gate.entered;
   const response=await call("POST","/v6/pt/test-authority/permits/"+s.permitId+"/revoke",{},undefined,true);
   assert.equal(response.statusCode,200,response.body);
   gate.release();await worker;
   const state=await snapshot(id,s.permitId);
   assert.equal(state.job.status,"FAILED");
   assert.equal(state.receipts.filter(x=>x.decision==="ALLOWED").length,0);
   assert.equal(state.ledger[0].state,"UNCERTAIN");
   assert.deepEqual([state.permit.consumed,state.permit.reserved],[1,0]);
  });
  await t.test("real cancellation during RESERVED admission settles orphan; no publication", {timeout:25000},async()=>{
   const s=await prepare(1),id=await queue(s.scopeId,s.keys),claim=await startManually(id),gate=barrier();
   const worker=processPtJob(TENANT,id,claim,{afterReservation:gate.block});
   await gate.entered;
   const response=await call("POST","/v6/pt/jobs/"+id+"/cancel");
   assert.equal(response.statusCode,200,response.body);
   gate.release();await worker;
   const state=await snapshot(id,s.permitId);
   assert.equal(state.job.status,"CANCELLED");
   assert.equal(state.reports,0);
   assert.equal(state.receipts.length,0);
   assert.equal(state.ledger[0].state,"UNCERTAIN");
   assert.deepEqual([state.permit.consumed,state.permit.reserved],[1,0]);
  });
  await t.test("emergency stop wins before final report commit after successful fixture evaluation", {timeout:25000},async()=>{
   const s=await prepare(1),id=await queue(s.scopeId,s.keys),claim=await startManually(id),gate=barrier();
   const worker=processPtJob(TENANT,id,claim,{beforePublication:gate.block});
   await gate.entered;
   const pre=await snapshot(id,s.permitId);
   assert.equal(pre.receipts.filter(x=>x.decision==="ALLOWED").length,1);
   assert.equal(pre.reports,0);
   const response=await call("POST","/v6/pt/test-authority/stop",{},undefined,true);
   assert.equal(response.statusCode,200,response.body);
   gate.release();await worker;
   const state=await snapshot(id,s.permitId);
   assert.equal(state.job.status,"CANCELLED");
   assert.equal(state.reports,0);
   assert.deepEqual([state.permit.consumed,state.permit.reserved],[1,0]);
   const resume=await call("POST","/v6/pt/test-authority/resume",{},undefined,true);
   assert.equal(resume.statusCode,200,resume.body);
  });
  await t.test("execution-slot capacity released after terminal worker state", {timeout:25000},async()=>{
   const s=await prepare(2,1),id=await queue(s.scopeId,s.keys);
   const denied=await call("POST","/v6/pt/scopes/"+s.scopeId+"/jobs",{operationKeys:s.keys},"qualification-job-"+randomUUID());
   assert.equal(denied.statusCode,409,denied.body);
   assert.equal(denied.json().error,"CONCURRENCY_LIMIT");
   assert.equal(await processOneJob(),true);
   const first=await snapshot(id,s.permitId);
   assert.equal(first.job.status,"COMPLETED");
   const secondId=await queue(s.scopeId,s.keys);
   assert.equal(await processOneJob(),true);
   const second=await snapshot(secondId,s.permitId);
   assert.equal(second.job.status,"COMPLETED");
   assert.deepEqual([second.permit.consumed,second.permit.reserved],[2,0]);
  });
  await t.test("two workers race on a reclaimed stale lease without fixture replay", {timeout:25000},async()=>{
   const s=await prepare(1,1),id=await queue(s.scopeId,s.keys),claimed=await claimJob();
   assert.equal(claimed?.assessment_id,id);
   await withWorkerTenant(TENANT,tx=>tx.query("UPDATE api_queue.api_assessment_queue SET locked_until=now()-interval '1 minute' WHERE assessment_id=$1",[id]));
   const calls=await Promise.all([processOneJob(),processOneJob()]);
   assert.equal(calls.filter(Boolean).length,1);
   const state=await snapshot(id,s.permitId);
   assert.equal(state.receipts.filter(x=>x.decision==="ALLOWED").length,1);
   assert.equal(state.ledger.length,1);
   assert.equal(state.permit.consumed,1);
   assert.equal(state.permit.reserved,0);
  });
 }finally{
  await inspector.end();
  await app.close();
  await pool.end();await workerPool.end();
 }
});
