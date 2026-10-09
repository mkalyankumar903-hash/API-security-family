import {test} from "node:test";
import assert from "node:assert/strict";
import {randomUUID} from "node:crypto";
import {spawn} from "node:child_process";
import {performance} from "node:perf_hooks";
import {
 migrate,claimJob,renewWorkerClaim,releaseUnstartedWorkerClaim,finishWorkerAttempt,
 withWorkerTenant,withTenant,closeDatabase,type WorkerClaim
} from "../packages/database/src/index.js";
import {makeApp} from "../packages/service/src/app.js";
import {processOneJob} from "../packages/worker/src/index.js";

const A="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",B="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const SPEC=JSON.stringify({openapi:"3.1.0",info:{title:"Fair worker queue",version:"1.0.0"},
 paths:{"/available":{get:{responses:{"200":{description:"synthetic offline"}}}}}});

test("Phase10 PostgreSQL: imbalanced tenants, parallel claims, bounded per-tenant active capacity, no starvation",async()=>{
 await migrate();const app=await makeApp();
 const created:{id:string;tenant:string;token:string}[]=[];
 const claimed:WorkerClaim[]=[];
 const api=(token:string,method:"POST"|"GET",url:string,payload?:object,key?:string)=>
  app.inject({method,url,payload,headers:{authorization:"Bearer "+token,...(key?{"idempotency-key":key}:{})}});
 try{
  for(const [tenant,token,depth] of [[A,"local-test-token-alpha",7],[B,"local-test-token-beta",1]] as const){
   const target=await api(token,"POST","/v1/targets",{name:"Fair "+randomUUID().slice(0,10),
    baseUrl:"https://fair-"+randomUUID()+".fixture.invalid",environment:"SYNTHETIC"});
   assert.equal(target.statusCode,201,target.body);
   const tid=target.json().id as string;
   const s=await api(token,"POST","/v1/targets/"+tid+"/specifications",{filename:"fair.json",content:SPEC});
   assert.equal(s.statusCode,201,s.body);
   for(let n=0;n<depth;n++){
    const j=await api(token,"POST","/v1/targets/"+tid+"/assessments",
     {specificationId:s.json().id,mode:"SPEC_ONLY"},"fair-"+randomUUID());
    assert.equal(j.statusCode,201,j.body);
    created.push({id:j.json().id as string,tenant,token});
   }
  }
  const begin=performance.now();
  const results=await Promise.all(Array.from({length:4},()=>claimJob()));
  const ms=performance.now()-begin;
  for(const result of results)if(result)claimed.push(result);
  assert.ok(claimed.length>=2,"multiple independent sessions claim valid work");
  const chosenA=claimed.filter(x=>x.tenant_id===A),chosenB=claimed.filter(x=>x.tenant_id===B);
  assert.ok(chosenA.length<=2,"tenant A cap enforced");
  assert.ok(chosenB.length>=1,"smaller tenant makes progress despite seven-to-one backlog");
  assert.equal(new Set(claimed.map(x=>x.assessment_id)).size,claimed.length,"no duplicate claim");
  assert.ok(ms<6000,"bounded synthetic claim coordination, not a production benchmark");
  for(const claim of claimed)assert.equal(await renewWorkerClaim(claim),true);
  const aQueue=await withWorkerTenant(A,tx=>tx.query("SELECT count(*)::int AS n FROM api_queue.api_assessment_queue WHERE tenant_id=$1",[A]));
  assert.equal(aQueue.rows[0].n,7,"unclaimed accepted work retained under backpressure");
  const bQueue=await withWorkerTenant(B,tx=>tx.query("SELECT count(*)::int AS n FROM api_queue.api_assessment_queue WHERE tenant_id=$1",[B]));
  assert.equal(bQueue.rows[0].n,1);
  const isolation=await withTenant(B,tx=>tx.query("SELECT count(*)::int AS n FROM api_worker_attempts WHERE assessment_id=ANY($1::uuid[])",[created.filter(x=>x.tenant===A).map(x=>x.id)]));
  assert.equal(isolation.rows[0].n,0);
  // Conservative stop: terminally cancel fixture-free jobs before drain. No new
  // permit budget, no synthetic fixture interaction and no historical deletion.
  for(const item of created){
   const cancel=await api(item.token,"POST","/v1/assessments/"+item.id+"/cancel",{});
   assert.equal(cancel.statusCode,200,cancel.body);
  }
  for(const claim of claimed)await finishWorkerAttempt(claim);
 }finally{
  for(const item of created){
   await withWorkerTenant(item.tenant,tx=>tx.query(
    "DELETE FROM api_queue.api_assessment_queue WHERE assessment_id=$1",[item.id]));
  }
  await app.close();await closeDatabase();
 }
});

test("Phase10 PostgreSQL: stop-aware claim-release fencing and genuine SIGTERM worker shutdown",async()=>{
 await migrate();const app=await makeApp();
 const token="local-test-token-alpha";
 const api=(method:"POST"|"GET",path:string,data?:object,key?:string)=>app.inject({
  method,url:path,payload:data,headers:{authorization:"Bearer "+token,...(key?{"idempotency-key":key}:{})}});
 let jobId:string|null=null;
 try{
  const target=await api("POST","/v1/targets",{name:"Graceful "+randomUUID().slice(0,7),
   baseUrl:"https://shutdown-"+randomUUID()+".fixture.invalid",environment:"SYNTHETIC"});
  assert.equal(target.statusCode,201,target.body);const tid=target.json().id as string;
  const spec=await api("POST","/v1/targets/"+tid+"/specifications",{filename:"shutdown.json",content:SPEC});
  assert.equal(spec.statusCode,201,spec.body);
  const job=await api("POST","/v1/targets/"+tid+"/assessments",
   {specificationId:spec.json().id,mode:"SPEC_ONLY"},"shutdown-"+randomUUID());
  assert.equal(job.statusCode,201,job.body);jobId=job.json().id as string;
  const already=new AbortController();already.abort();
  assert.equal(await processOneJob({signal:already.signal}),false,"stopped worker never starts a new claim");
  const first=await claimJob();assert.equal(first?.assessment_id,jobId);
  assert.equal(await releaseUnstartedWorkerClaim(first!),true);
  assert.equal(await releaseUnstartedWorkerClaim(first!),false,"release is idempotent and fenced");
  assert.equal(await renewWorkerClaim(first!),false,"released owner cannot heartbeat");
  const following=await claimJob();
  assert.equal(following?.assessment_id,jobId);
  assert.equal(following?.claim_generation,2);
  assert.equal(await renewWorkerClaim(first!),false,"old attempt must not regain ownership");
  assert.equal(await releaseUnstartedWorkerClaim(following!),true);
  const attempts=await withTenant(A,tx=>tx.query(
   "SELECT state,failure_code FROM api_worker_attempts WHERE assessment_id=$1 ORDER BY claim_generation",[jobId]));
  assert.equal(attempts.rowCount,2);
  assert.ok(attempts.rows.every(x=>x.state==="LOST"&&x.failure_code==="SHUTDOWN_BEFORE_EXECUTION"));
  const cancellation=await api("POST","/v1/assessments/"+jobId+"/cancel",{});
  assert.equal(cancellation.statusCode,200,cancellation.body);

  const child=spawn(process.execPath,["--import","tsx","packages/worker/src/main.ts"],{
   env:process.env,stdio:["ignore","pipe","pipe","ipc"]});
  try{
   await new Promise<void>((resolve,reject)=>{
    const t=setTimeout(()=>reject(new Error("WORKER_STARTUP_IPC_TIMEOUT")),12000);
    child.once("message",m=>{clearTimeout(t);
     if((m as {kind?:string}).kind==="READY")resolve();
     else reject(new Error("UNEXPECTED_READY_PAYLOAD"));});
    child.once("error",reject);
    child.once("exit",(code,signal)=>{clearTimeout(t);reject(new Error("WORKER_EXIT_EARLY_"+code+"_"+signal));});
   });
   const terminated=new Promise<{code:number|null;signal:NodeJS.Signals|null}>(resolve=>
    child.once("exit",(code,signal)=>resolve({code,signal})));
   child.kill("SIGTERM");
   const exit=await Promise.race([terminated,new Promise<never>((_,reject)=>
    setTimeout(()=>reject(new Error("WORKER_SIGTERM_DRAIN_TIMEOUT")),7000))]);
   assert.deepEqual(exit,{code:0,signal:null},"SIGTERM graceful worker releases all PostgreSQL connections");
  }finally{if(child.exitCode===null&&!child.killed)child.kill("SIGKILL");}
 }finally{
  if(jobId)await withWorkerTenant(A,tx=>tx.query(
   "DELETE FROM api_queue.api_assessment_queue WHERE assessment_id=$1",[jobId]));
  await app.close();await closeDatabase();
 }
});
