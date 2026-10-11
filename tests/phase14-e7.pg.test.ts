/** Phase14 E7: independently measured actual PostgreSQL retry/backoff and lease recovery.
 * 10 distinct first-write fixtures, 2 warmups plus 8 measured samples. This
 * is not a production time guarantee or a synthetic-only mocked planner.
 */
import {test,after} from "node:test";
import assert from "node:assert/strict";
import {randomUUID} from "node:crypto";
import {performance} from "node:perf_hooks";
import {makeApp} from "../packages/service/src/app.js";
import {migrate,claimJob,withWorkerTenant,withTenant,closeDatabase,
 renewWorkerClaim,releaseUnstartedWorkerClaim} from "../packages/database/src/index.js";
import {scheduleConservativeRetry} from "../packages/worker/src/safety-retry.js";
const A="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const source=JSON.stringify({openapi:"3.1.0",info:{title:"E7 retry",version:"1"},
 paths:{"/fixture":{get:{responses:{"200":{description:"synthetic only"}}}}}});
after(async()=>{await closeDatabase();});
test("Phase14 E7 actual committed transient backoff and generation-fenced recovery distributions",async()=>{
 await migrate();
 const app=await makeApp(),warmup=2,iterations=10;
 const reserveMs:number[]=[],reclaimMs:number[]=[],cpu=process.cpuUsage(),heap=process.memoryUsage().heapUsed;
 const req=(method:"POST"|"GET",url:string,payload?:object,key?:string)=>app.inject({
  method,url,payload,headers:{authorization:"Bearer local-test-token-alpha",
   ...(key?{"idempotency-key":key}:{})}});
 const ok=(x:{statusCode:number;body:string;json:()=>Record<string,unknown>},code:number)=>{
  assert.equal(x.statusCode,code,x.body);return x.json();
 };
 try{
  for(let i=0;i<iterations;i++){
   const suffix=randomUUID().slice(0,8);
   const target=ok(await req("POST","/v1/targets",{
    name:"E7 "+suffix,baseUrl:"https://e7-"+suffix+".fixture.invalid",environment:"SYNTHETIC"}),201);
   const targetId=target.id as string;
   const spec=ok(await req("POST","/v1/targets/"+targetId+"/specifications",{
    filename:"e7.json",content:source}),201);
   const created=ok(await req("POST","/v1/targets/"+targetId+"/assessments",{
    specificationId:spec.id,mode:"SPEC_ONLY"},"e7-"+randomUUID()),201);
   const jobId=created.id as string,lease=await claimJob();
   assert.equal(lease?.assessment_id,jobId,"only this new eligible test fixture may be claimed");
   const started=performance.now();
   const result=await scheduleConservativeRetry(lease!,{code:"08006"});
   const elapsed=performance.now()-started;assert.equal(result,"RETRY_SCHEDULED");
   if(i>=warmup)reserveMs.push(elapsed);
   const db=await withWorkerTenant(A,tx=>tx.query(
    "SELECT retry_count,claim_token,next_eligible_at,last_error_code FROM api_queue.api_assessment_queue WHERE assessment_id=$1",[jobId]));
   assert.equal(db.rows[0].retry_count,1);assert.equal(db.rows[0].claim_token,null);
   assert.equal(db.rows[0].last_error_code,"TRANSIENT_08006");
   const backoff=new Date(db.rows[0].next_eligible_at).getTime()-Date.now();
   assert(backoff>0&&backoff<=2100,"real 2-second next eligible time");
   assert.equal(await renewWorkerClaim(lease!),false,"previous generation must be fenced");
   await withWorkerTenant(A,tx=>tx.query(
    "UPDATE api_queue.api_assessment_queue SET next_eligible_at=clock_timestamp()-interval '1 second' WHERE assessment_id=$1",[jobId]));
   const recoverStart=performance.now(),successor=await claimJob();
   const recoveryTime=performance.now()-recoverStart;
   assert.equal(successor?.assessment_id,jobId);assert.notEqual(successor?.claim_token,lease!.claim_token);
   assert.equal(successor?.claim_generation,lease!.claim_generation+1);
   if(i>=warmup)reclaimMs.push(recoveryTime);
   assert.equal(await releaseUnstartedWorkerClaim(successor!),true);
   const cancel=await req("POST","/v1/assessments/"+jobId+"/cancel",{});
   ok(cancel,200);
   const final=await withTenant(A,async tx=>{
    const a=await tx.query("SELECT status FROM api_assessments WHERE id=$1",[jobId]);
    const events=await tx.query("SELECT kind FROM api_worker_events WHERE assessment_id=$1",[jobId]);
    const reports=await tx.query("SELECT count(*)::int AS n FROM api_reports WHERE assessment_id=$1",[jobId]);
    return {status:a.rows[0]?.status,events:events.rows.map(x=>x.kind),reports:reports.rows[0].n};
   });
   assert.equal(final.status,"CANCELLED");assert.equal(final.reports,0);
   assert(final.events.includes("RETRY_SCHEDULED"));
  }
  const stats=(values:number[])=>{
   const v=[...values].sort((a,b)=>a-b);assert.equal(v.length,8);
   assert(v.every(n=>n>=0&&Number.isFinite(n)));
   return {medianMs:Number(v[3]!.toFixed(3)),
    p95Ms:Number(v[Math.ceil(v.length*.95)-1]!.toFixed(3)),samples:v.length};
  };
  const consumption=process.cpuUsage(cpu);
  console.log("PHASE14_E7_REAL_RETRY_RECOVERY "+JSON.stringify({
   reserve:stats(reserveMs),generationReclaim:stats(reclaimMs),
   warmup,fixtureCount:iterations,concurrency:1,firstWrites:true,errors:0,
   cpuUserMicros:consumption.user,cpuSystemMicros:consumption.system,
   heapDeltaBytes:process.memoryUsage().heapUsed-heap,
   source:"scheduleConservativeRetry actual PG commit; claimJob actual next-eligible lease takeover",
   backoffSeconds:2,retryCount:1,tenantRls:true,oldGenerationDenied:true,
   customerNetworkRequests:0,environment:"GitHub-hosted Node22 PostgreSQL16",
   strictBudget:"correct state + bounded real DB backoff + zero error only; no shared-runner p95 hard SLA",
   productionSlo:false}));
 }finally{await app.close();}
});


test("Phase14 E7 actual 2-4-8 second committed retry distribution and terminal exhaustion",async()=>{
 await migrate();const app=await makeApp();
 const warmup=2,fixtures=10,measured=[[],[],[],[]] as number[][];
 const scheduledBackoffs=[2,4,8],cpu=process.cpuUsage(),heap=process.memoryUsage().heapUsed;
 const req=(url:string,data:object,key?:string)=>app.inject({method:"POST",url,payload:data,headers:{
  authorization:"Bearer local-test-token-alpha",...(key?{"idempotency-key":key}:{})}});
 const ok=(r:{statusCode:number;body:string;json:()=>Record<string,unknown>},status:number)=>{
  assert.equal(r.statusCode,status,r.body);return r.json();
 };
 try{
  for(let i=0;i<fixtures;i++){
   const suffix=randomUUID().slice(0,8);
   const tid=ok(await req("/v1/targets",{name:"E7 exhaust "+suffix,
    environment:"SYNTHETIC",baseUrl:"https://exhaust-"+suffix+".fixture.invalid"}),201).id as string;
   const spec=ok(await req("/v1/targets/"+tid+"/specifications",{
    filename:"e7-exhaust.json",content:source}),201).id as string;
   const id=ok(await req("/v1/targets/"+tid+"/assessments",{
    mode:"SPEC_ONLY",specificationId:spec},"exhaust-"+randomUUID()),201).id as string;
   let lease=await claimJob();assert.equal(lease?.assessment_id,id);
   for(let n=0;n<4;n++){
    const beginning=performance.now();
    const classification=await scheduleConservativeRetry(lease!,{code:"08006"});
    const elapsed=performance.now()-beginning;
    assert.equal(classification,n===3?"RETRY_EXHAUSTED":"RETRY_SCHEDULED");
    if(i>=warmup)measured[n]!.push(elapsed);
    if(n===3)break;
    const state=await withWorkerTenant(A,tx=>tx.query(
     "SELECT retry_count,claim_token,next_eligible_at,last_error_code FROM api_queue.api_assessment_queue WHERE assessment_id=$1",[id]));
    assert.equal(state.rows[0].retry_count,n+1);
    assert.equal(state.rows[0].claim_token,null);
    assert.equal(state.rows[0].last_error_code,"TRANSIENT_08006");
    const observed=(new Date(state.rows[0].next_eligible_at).getTime()-Date.now())/1000;
    assert(observed>0&&observed<=scheduledBackoffs[n]!+0.2,
     "real next_eligible_at must match observed bounded 2/4/8 second backoff");
    assert.equal(await renewWorkerClaim(lease!),false);
    await withWorkerTenant(A,tx=>tx.query(
     "UPDATE api_queue.api_assessment_queue SET next_eligible_at=clock_timestamp()-interval '1 second' WHERE assessment_id=$1",[id]));
    const successor=await claimJob();
    assert.equal(successor?.assessment_id,id);assert.notEqual(successor?.claim_token,lease!.claim_token);
    assert.equal(successor?.claim_generation,lease!.claim_generation+1);
    lease=successor;
   }
   const committed=await withTenant(A,async tx=>{
    const assessment=await tx.query("SELECT status,error_code FROM api_assessments WHERE id=$1",[id]);
    const attempts=await tx.query("SELECT state,failure_code FROM api_worker_attempts WHERE assessment_id=$1 ORDER BY claim_generation",[id]);
    const events=await tx.query("SELECT kind,code FROM api_worker_events WHERE assessment_id=$1 ORDER BY occurred_at",[id]);
    const quarantine=await tx.query("SELECT reason_code,attempts FROM api_worker_quarantine WHERE assessment_id=$1",[id]);
    const report=await tx.query("SELECT count(*)::int AS n FROM api_reports WHERE assessment_id=$1",[id]);
    return {assessment:assessment.rows[0],attempts:attempts.rows,events:events.rows,
     quarantine:quarantine.rows[0],reports:report.rows[0].n};
   });
   assert.deepEqual(committed.assessment,{status:"FAILED",error_code:"WORKER_RETRY_EXHAUSTED"});
   assert.equal(committed.attempts.length,4);
   assert.equal(committed.events.filter(x=>x.kind==="RETRY_SCHEDULED").length,3);
   assert.equal(committed.events.filter(x=>x.kind==="RETRY_EXHAUSTED").length,1);
   assert.deepEqual(committed.quarantine,{reason_code:"WORKER_RETRY_EXHAUSTED",attempts:4});
   assert.equal(committed.reports,0);
   assert.equal((await withWorkerTenant(A,tx=>tx.query(
    "SELECT 1 FROM api_queue.api_assessment_queue WHERE assessment_id=$1",[id]))).rowCount,0);
  }
  const stat=(s:number[])=>{
   assert.equal(s.length,fixtures-warmup);
   assert(s.every(v=>v>=0&&Number.isFinite(v)));
   const sorted=[...s].sort((a,b)=>a-b);
   return {samples:sorted.length,medianMs:Number(sorted[3]!.toFixed(3)),
    p95Ms:Number(sorted[7]!.toFixed(3))};
  };
  const used=process.cpuUsage(cpu);
  console.log("PHASE14_E7_FULL_RETRY_EXHAUSTION "+JSON.stringify({
   stages:["2s","4s","8s","EXHAUSTED"].map((name,index)=>({name,...stat(measured[index]!)})),
   warmup,fixtures,concurrency:1,errors:0,
   cpuUserMicros:used.user,cpuSystemMicros:used.system,
   heapDeltaBytes:process.memoryUsage().heapUsed-heap,
   source:"scheduleConservativeRetry actual PostgreSQL retry_count/next_eligible_at and terminal quarantine",
   reportCount:0,billable:false,customerNetworkRequests:0,productionSlo:false,
   hardP95Budget:null,reason:"8 shared GitHub runner samples cannot justify production hard latency budget"}));
 }finally{await app.close();}
});
