/** Phase10 security acceptance: seven controlled, independently connected PG races.
 * Each gate is a real row lock in one PostgreSQL backend; actor transactions
 * execute in other application/worker backends. pg_stat_activity confirms
 * the actual blocked lock wait before the gate is released. */
import {test,after} from "node:test";
import assert from "node:assert/strict";
import {randomUUID} from "node:crypto";
import {readFileSync} from "node:fs";
import {Pool,type PoolClient} from "pg";
import {migrate,claimJob,renewWorkerClaim,releaseUnstartedWorkerClaim,withTenant,withWorkerTenant,closeDatabase} from "../packages/database/src/index.js";
import {scheduleConservativeRetry} from "../packages/worker/src/safety-retry.js";
import {makeApp} from "../packages/service/src/app.js";
const TENANT="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const SPEC=JSON.stringify({openapi:"3.1.0",info:{title:"Concurrent leases",version:"1.0.0"},
 paths:{"/health":{get:{responses:{"200":{description:"Synthetic only"}}}}}});
const PT_SPEC=readFileSync(new URL("../fixtures/phase07-security.openapi.json",import.meta.url),"utf8");
const observer=new Pool({connectionString:process.env.MIGRATION_DATABASE_URL,max:2});
after(async()=>{await observer.end();await closeDatabase();});
const delay=(ms:number)=>new Promise<void>(resolve=>setTimeout(resolve,ms));
type Resp={statusCode:number;body:string;json:()=>Record<string,unknown>};
async function lockWait(queryPart:string,atLeast=1):Promise<void>{
 const start=Date.now();
 while(Date.now()-start<7000){
  const q=await observer.query(`SELECT pid,query,wait_event FROM pg_stat_activity
   WHERE datname=current_database() AND state='active'
    AND wait_event_type='Lock' AND query ILIKE $1`,["%"+queryPart+"%"]);
  if(q.rows.length>=atLeast)return;
  await delay(25);
 }
 throw new Error("CONTROLLED_PG_LOCK_WAIT_NOT_OBSERVED: "+queryPart+" ("+atLeast+")");
}
function heldRow(sql:string,args:unknown[],mutation?:(tx:PoolClient)=>Promise<void>){
 let signalReady!:()=>void,signalRelease!:()=>void;
 const ready=new Promise<void>(resolve=>signalReady=resolve);
 const unblocked=new Promise<void>(resolve=>signalRelease=resolve);
 const done=withWorkerTenant(TENANT,async tx=>{
  await tx.query(sql,args);
  signalReady();
  await unblocked;
  if(mutation)await mutation(tx);
 });
 return {ready,release:signalRelease,done};
}
test("Phase10 independent-session 25-case security acceptance rework: exact #7,#9,#10,#12,#13,#15,#16",async t=>{
 await migrate();
 const app=await makeApp();
 const req=(method:"GET"|"POST",url:string,payload?:object,key?:string,authority=false)=>app.inject({
  method,url,payload,headers:{"authorization":"Bearer local-test-token-alpha",
   ...(key?{"idempotency-key":key}:{}),
   ...(authority?{"x-pt-authority-key":process.env.PT_TEST_AUTHORITY_KEY??""}:{})}}) as Promise<Resp>;
 const call=async(method:"GET"|"POST",url:string,payload?:object,key?:string,authority=false,status=201)=>{
  const x=await req(method,url,payload,key,authority);assert.equal(x.statusCode,status,x.body);return x.json();
 };
 const suffix=randomUUID().slice(0,8);
 try{
  const target=await call("POST","/v1/targets",{name:"Acceptance "+suffix,
   environment:"SYNTHETIC",baseUrl:"https://phase10-acceptance-"+suffix+".fixture.invalid"});
  const tid=target.id as string;
  const spec=await call("POST","/v1/targets/"+tid+"/specifications",{filename:"acceptance.json",content:SPEC});
  const sid=spec.id as string;
  const makeJob=async()=> (await call("POST","/v1/targets/"+tid+"/assessments",
   {specificationId:sid,mode:"SPEC_ONLY"},"acceptance-"+randomUUID())).id as string;
  const read=async(id:string)=>withWorkerTenant(TENANT,async tx=>{
   const queue=await tx.query("SELECT claim_token,claim_generation,retry_count FROM api_queue.api_assessment_queue WHERE assessment_id=$1",[id]);
   const assessment=await tx.query("SELECT status,error_code FROM api_assessments WHERE id=$1",[id]);
   const attempts=await tx.query("SELECT state,claim_generation FROM api_worker_attempts WHERE assessment_id=$1 ORDER BY claim_generation",[id]);
   const report=await tx.query("SELECT count(*)::int AS n FROM api_reports WHERE assessment_id=$1",[id]);
   const ptReport=await tx.query("SELECT count(*)::int AS n FROM api_pt9_reports WHERE assessment_id=$1",[id]);
   const evaluations=await tx.query("SELECT state FROM api_pt_detection_evaluations WHERE assessment_id=$1",[id]);
   return {queue:queue.rows[0]??null,status:assessment.rows[0]?.status,error:assessment.rows[0]?.error_code,
    attempts:attempts.rows,reports:report.rows[0].n,ptReports:ptReport.rows[0].n,evaluations:evaluations.rows};
  });
  const cancel=async(id:string)=>req("POST","/v1/assessments/"+id+"/cancel",{});
  const ptSpec=await call("POST","/v2/targets/"+tid+"/specifications/imports",
   {filename:"phase07-security.openapi.json",content:PT_SPEC},"acceptance-import-"+randomUUID());
  const op=(await call("GET","/v2/specifications/"+ptSpec.specificationId+"/operations?limit=100",undefined,undefined,false,200)) as unknown as {method:string;path:string;key:string}[];
  const keys=["/pt/account","/pt/resources/bob","/pt/admin","/pt/confidential"].map(path=>{
   const key=op.find(x=>x.method==="GET"&&x.path===path)?.key;assert.ok(key);return key;
  });
  const finishPt=async(id:string)=>{
   const state=await read(id);
   if(state.status==="PROCESSING"||state.status==="QUEUED"){
    const cancellation=await req("POST","/v9/pt/orchestrations/"+id+"/cancel",{});
    assert.equal(cancellation.statusCode,200,cancellation.body);
   }
   const after=await read(id);
   assert.notEqual(after.status,"COMPLETED");
   assert.equal(after.queue,null,"no aborted PT job can hijack the next deterministic claim");
   assert.equal(after.reports+after.ptReports,0);
  };
  const pt=async()=>{
   const scope=await call("POST","/v6/pt/targets/"+tid+"/scopes",{
    specificationId:ptSpec.specificationId,operationKeys:keys,fixtureId:"pt-security-v1",
    exclusions:[],maxEvaluations:4,ratePerMinute:4,maxConcurrency:1,
    deadlineMs:30000,validityMinutes:15},"acceptance-scope-"+randomUUID());
   await call("POST","/v6/pt/scopes/"+scope.id+"/request-authorization",{});
   const permit=await call("POST","/v6/pt/test-authority/scopes/"+scope.id+"/issue",{},undefined,true);
   const job=await call("POST","/v9/pt/scopes/"+scope.id+"/orchestrations",{
    policyId:"SYNTHETIC_PT_AUTHORIZATION_FOCUSED",profile:"SECURE_BASELINE"
   },"acceptance-pt-"+randomUUID());
   const claim=await claimJob();assert.equal(claim?.assessment_id,job.id);
   return {id:job.id as string,permit:permit.id as string,claim:claim!};
  };
  await t.test("#7 stale cancellation/release vs current-generation customer cancellation",async()=>{
   const id=await makeJob(),old=(await claimJob())!;
   assert.equal(old.assessment_id,id);
   await withWorkerTenant(TENANT,tx=>tx.query("UPDATE api_queue.api_assessment_queue SET locked_until=clock_timestamp()-interval '1 second' WHERE assessment_id=$1",[id]));
   const current=(await claimJob())!;assert.equal(current.claim_generation,old.claim_generation+1);
   const gate=heldRow("SELECT 1 FROM api_queue.api_assessment_queue WHERE assessment_id=$1 FOR UPDATE",[id]);
   await gate.ready;
   try{
    const stale=releaseUnstartedWorkerClaim(old);
    await lockWait("api_assessment_queue");
    const cancellation=cancel(id);
    gate.release();
    assert.equal(await stale,false,"old generation may not erase the replacement claim");
    const c=await cancellation;assert.equal(c.statusCode,200,c.body);
   }finally{gate.release();await gate.done;}
   const state=await read(id);
   assert.equal(state.status,"CANCELLED");assert.equal(state.queue,null);
   assert.equal(state.reports+state.ptReports,0);
   assert.equal(state.attempts.length,2);
   assert.ok(state.attempts.every(x=>x.state!=="ACTIVE"));
  });
  await t.test("#9 old worker races newer worker renewal on replacement lease",async()=>{
   const id=await makeJob(),old=(await claimJob())!;
   await withWorkerTenant(TENANT,tx=>tx.query("UPDATE api_queue.api_assessment_queue SET locked_until=clock_timestamp()-interval '1 second' WHERE assessment_id=$1",[id]));
   const current=(await claimJob())!;assert.equal(current.claim_generation,old.claim_generation+1);
   const gate=heldRow("SELECT 1 FROM api_queue.api_assessment_queue WHERE assessment_id=$1 FOR UPDATE",[id]);await gate.ready;
   try{
    const former=renewWorkerClaim(old),fresh=renewWorkerClaim(current);
    await lockWait("api_assessment_queue",2);
    gate.release();
    assert.deepEqual(await Promise.all([former,fresh]),[false,true]);
   }finally{gate.release();await gate.done;}
   const state=await read(id);
   assert.equal(state.queue.claim_token,current.claim_token);assert.equal(Number(state.queue.claim_generation),2);
   assert.deepEqual(state.attempts.map(x=>x.state),["LOST","ACTIVE"]);
   assert.equal(state.reports+state.ptReports,0);
   assert.equal((await cancel(id)).statusCode,200);
  });
  await t.test("#10 renewal loses to expiring lease under PG row lock",async()=>{
   const id=await makeJob(),claim=(await claimJob())!;
   const gate=heldRow("SELECT 1 FROM api_queue.api_assessment_queue WHERE assessment_id=$1 FOR UPDATE",[id],
    tx=>tx.query("UPDATE api_queue.api_assessment_queue SET locked_until=clock_timestamp()-interval '1 second' WHERE assessment_id=$1",[id]).then(()=>{}));
   await gate.ready;
   try{
    const renewal=renewWorkerClaim(claim);
    await lockWait("api_assessment_queue");
    gate.release();assert.equal(await renewal,false);
   }finally{gate.release();await gate.done;}
   const state=await read(id);
   assert.equal(state.status,"PROCESSING");assert.equal(state.reports+state.ptReports,0);
   assert.equal(Number(state.queue.claim_generation),1);
   assert.equal((await cancel(id)).statusCode,200);
  });
  await t.test("#12 renewal vs trusted emergency stop, stopped authority wins",async()=>{
   const j=await pt();
   // Trusted resume materializes the tenant stop record when absent.
   assert.equal((await req("POST","/v6/pt/test-authority/resume",{},undefined,true)).statusCode,200);
   const gate=heldRow("SELECT 1 FROM api_pt_stop WHERE tenant_id=$1 FOR UPDATE",[TENANT]);await gate.ready;
   try{
    const stopping=req("POST","/v6/pt/test-authority/stop",{},undefined,true);
    await lockWait("api_pt_stop");
    const renewal=renewWorkerClaim(j.claim);
    await lockWait("api_pt_stop",2);
    gate.release();
    const st=await stopping;assert.equal(st.statusCode,200,st.body);
    assert.equal(await renewal,false);
   }finally{gate.release();await gate.done;}
   const state=await read(j.id);
   assert.notEqual(state.status,"COMPLETED");assert.equal(state.reports+state.ptReports,0);
   assert.equal((await req("POST","/v6/pt/test-authority/resume",{},undefined,true)).statusCode,200);
   await finishPt(j.id);
  });
  await t.test("#13 renewal vs deadline transaction, deadline wins",async()=>{
   const j=await pt();
   const gate=heldRow("SELECT 1 FROM api_pt_jobs WHERE assessment_id=$1 FOR UPDATE",[j.id],
    tx=>tx.query("UPDATE api_pt_jobs SET job_deadline=clock_timestamp()-interval '1 second' WHERE assessment_id=$1",[j.id]).then(()=>{}));
   await gate.ready;
   try{
    const renewal=renewWorkerClaim(j.claim);
    await lockWait("api_pt_jobs");
    gate.release();assert.equal(await renewal,false);
   }finally{gate.release();await gate.done;}
   assert.equal(await scheduleConservativeRetry(j.claim,{code:"08006"}),"NOT_RETRYABLE");
   const state=await read(j.id);
   assert.equal(state.reports+state.ptReports,0);assert.equal(state.evaluations.length,0);
   await finishPt(j.id);
  });
  await t.test("#15 retry vs trusted permit revocation, revocation wins",async()=>{
   const j=await pt();
   const gate=heldRow("SELECT 1 FROM api_pt_permits WHERE id=$1 FOR UPDATE",[j.permit]);await gate.ready;
   try{
    const revoke=req("POST","/v6/pt/test-authority/permits/"+j.permit+"/revoke",{},undefined,true);
    await lockWait("api_pt_permits");
    const retry=scheduleConservativeRetry(j.claim,{code:"08006"});
    await lockWait("api_pt_permits",2);
    gate.release();
    const response=await revoke;assert.equal(response.statusCode,200,response.body);
    assert.equal(await retry,"NOT_RETRYABLE");
   }finally{gate.release();await gate.done;}
   const state=await read(j.id);
   assert.equal(Number(state.queue.retry_count),0,"revocation cannot buy a new retry window");
   assert.equal(state.reports+state.ptReports,0);assert.equal(state.evaluations.length,0);
   const b=await withTenant(TENANT,tx=>tx.query("SELECT consumed,reserved FROM api_pt_permits WHERE id=$1",[j.permit]));
   assert.equal(b.rows[0].consumed,0);assert.equal(b.rows[0].reserved,0);
   await finishPt(j.id);
  });
  await t.test("#16 retry exhaustion vs concurrent terminal commit, terminal wins",async()=>{
   const id=await makeJob();
   let claim=(await claimJob())!;
   for(let n=0;n<3;n++){
    assert.equal(await scheduleConservativeRetry(claim,{code:"08006"}),"RETRY_SCHEDULED");
    await withWorkerTenant(TENANT,tx=>tx.query("UPDATE api_queue.api_assessment_queue SET next_eligible_at=clock_timestamp()-interval '1 second' WHERE assessment_id=$1",[id]));
    claim=(await claimJob())!;
   }
   const gate=heldRow("SELECT 1 FROM api_assessments WHERE id=$1 FOR UPDATE",[id],
    tx=>tx.query("UPDATE api_assessments SET status='FAILED',error_code='SYNTHETIC_TERMINAL_RACE',completed_at=clock_timestamp() WHERE id=$1",[id]).then(()=>{}));
   await gate.ready;
   try{
    const exhausted=scheduleConservativeRetry(claim,{code:"08006"});
    await lockWait("api_assessments");
    gate.release();assert.equal(await exhausted,"STALE");
   }finally{gate.release();await gate.done;}
   const state=await read(id);
   assert.equal(state.status,"FAILED");assert.equal(state.error,"SYNTHETIC_TERMINAL_RACE");
   assert.equal(Number(state.queue.retry_count),3,"terminal must not schedule retry #4");
   assert.equal(state.reports+state.ptReports,0);
   const q=await withTenant(TENANT,tx=>tx.query("SELECT count(*)::int AS n FROM api_worker_quarantine WHERE assessment_id=$1",[id]));
   assert.equal(q.rows[0].n,0,"a competing terminal is not retry-exhaustion quarantine");
  });
 }finally{
  await req("POST","/v6/pt/test-authority/resume",{},undefined,true).catch(()=>null);
  await app.close();
 }
});
