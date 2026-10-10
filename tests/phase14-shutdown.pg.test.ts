/** GitHub-hosted real worker SIGTERM, bounded forced deadline and database recovery. */
import {test,after} from "node:test";
import assert from "node:assert/strict";
import {randomUUID} from "node:crypto";
import {spawn,type ChildProcess} from "node:child_process";
import {performance} from "node:perf_hooks";
import {makeApp} from "../packages/service/src/app.js";
import {migrate,withWorkerTenant,withTenant,renewWorkerClaim,releaseUnstartedWorkerClaim,
 closeDatabase,type WorkerClaim} from "../packages/database/src/index.js";
const TENANT="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const SPEC=JSON.stringify({openapi:"3.1.0",info:{title:"Shutdown isolation",version:"1"},
 paths:{"/health":{get:{responses:{"200":{description:"synthetic offline"}}}}}});
after(async()=>{await closeDatabase();});
const sleepers=new Set<ChildProcess>();
function spawnWorker(mode?:string){
 const child=spawn(process.execPath,["--import","tsx","packages/worker/src/main.ts"],{
  env:{...process.env,NODE_ENV:"test",SYNTHETIC_AUTH_ENABLED:"true",
   GITHUB_ACTIONS:"true",PHASE14_TEST_SHUTDOWN_MS:"450",
   ...(mode?{PHASE14_TEST_CLAIM_BARRIER:mode}:{})},
  stdio:["ignore","pipe","pipe","ipc"]
 });
 sleepers.add(child);child.once("exit",()=>sleepers.delete(child));
 return child;
}
function stage(child:ChildProcess,kind:string,ms=8000):Promise<{kind:string;assessmentId?:string;claimGeneration?:number}>{
 return new Promise((resolve,reject)=>{
  const timeout=setTimeout(()=>{cleanup();reject(new Error("PHASE14_CHILD_STAGE_TIMEOUT_"+kind));},ms);
  const onMsg=(value:unknown)=>{
   const m=value as {kind?:string;assessmentId?:string;claimGeneration?:number};
   if(m.kind===kind){cleanup();resolve(m as {kind:string;assessmentId?:string;claimGeneration?:number});}
  };
  const onExit=(code:number|null,signal:NodeJS.Signals|null)=>{
   cleanup();reject(new Error("PHASE14_PREMATURE_EXIT_"+code+"_"+signal));
  };
  const cleanup=()=>{clearTimeout(timeout);child.off("message",onMsg);child.off("exit",onExit);};
  child.on("message",onMsg);child.once("exit",onExit);
 });
}
function exitChild(child:ChildProcess,ms=3500):Promise<{code:number|null;signal:NodeJS.Signals|null;elapsedMs:number}>{
 const start=performance.now();
 return new Promise((resolve,reject)=>{
  const t=setTimeout(()=>reject(new Error("PHASE14_SHUTDOWN_DEADLINE_BREACH")),ms);
  child.once("exit",(code,signal)=>{clearTimeout(t);resolve({code,signal,elapsedMs:performance.now()-start});});
 });
}
async function newJob(){
 const app=await makeApp();
 const post=(url:string,data:object,key?:string)=>app.inject({
  method:"POST",url,payload:data,headers:{"authorization":"Bearer local-test-token-alpha",
   ...(key?{"idempotency-key":key}:{})}});
 try{
  const t=await post("/v1/targets",{name:"Shutdown "+randomUUID().slice(0,8),
   environment:"SYNTHETIC",baseUrl:"https://shutdown-"+randomUUID()+".fixture.invalid"});
  assert.equal(t.statusCode,201,t.body);
  const targetId=t.json().id as string;
  const spec=await post("/v1/targets/"+targetId+"/specifications",{filename:"shutdown.json",content:SPEC});
  assert.equal(spec.statusCode,201,spec.body);
  const job=await post("/v1/targets/"+targetId+"/assessments",{specificationId:spec.json().id,mode:"SPEC_ONLY"},"shutdown-"+randomUUID());
  assert.equal(job.statusCode,201,job.body);return job.json().id as string;
 }finally{await app.close();}
}
async function snapshot(id:string){
 return withTenant(TENANT,async tx=>{
  const a=await tx.query("SELECT status,error_code FROM api_assessments WHERE id=$1",[id]);
  const report=await tx.query("SELECT count(*)::int AS n FROM api_reports WHERE assessment_id=$1",[id]);
  const ledger=await tx.query("SELECT count(*)::int AS n FROM api_v13_usage_ledger WHERE source_report_id IN (SELECT id FROM api_pt9_reports WHERE assessment_id=$1)",[id]);
  const attempts=await tx.query("SELECT state,claim_generation FROM api_worker_attempts WHERE assessment_id=$1 ORDER BY claim_generation",[id]);
  return {status:a.rows[0].status,reports:report.rows[0].n,ledger:ledger.rows[0].n,attempts:attempts.rows};
 });
}
test("Phase14 genuine idle SIGTERM gracefully drains and closes PostgreSQL connections",async()=>{
 await migrate();const child=spawnWorker();
 try{
  const ready=stage(child,"READY");await ready;
  const end=exitChild(child);child.kill("SIGTERM");const exited=await end;
  assert.deepEqual([exited.code,exited.signal],[0,null]);assert(exited.elapsedMs<3000);
 }finally{if(child.exitCode===null)child.kill("SIGKILL");}
});
test("Phase14 genuine active claim cooperative SIGTERM releases unstarted lease and forbids success",async()=>{
 const id=await newJob(),child=spawnWorker("cooperative");
 try{
  const ready=stage(child,"READY");await ready;
  const claimed=await stage(child,"PHASE14_CLAIM_HELD");
  assert.equal(claimed.assessmentId,id);
  const ended=exitChild(child);child.kill("SIGTERM");
  const exit=await ended;assert.deepEqual([exit.code,exit.signal],[0,null]);assert(exit.elapsedMs<3000);
  const db=await snapshot(id);
  assert.equal(db.status,"PROCESSING");
  assert.equal(db.reports,0);assert.equal(db.ledger,0);
  assert.equal(db.attempts[0].state,"LOST");
 }finally{if(child.exitCode===null)child.kill("SIGKILL");}
});
test("Phase14 real blocked worker exceeds bounded deadline then fresh worker recovers fenced PostgreSQL claim",async()=>{
 const id=await newJob(),original=spawnWorker("stalled");
 try{
  await stage(original,"READY");
  const held=await stage(original,"PHASE14_CLAIM_HELD");assert.equal(held.assessmentId,id);
  const lease=await withWorkerTenant(TENANT,async tx=>{
   const row=await tx.query("SELECT claim_token,claim_generation FROM api_queue.api_assessment_queue WHERE assessment_id=$1",[id]);
   const attempt=await tx.query("SELECT id FROM api_worker_attempts WHERE assessment_id=$1 AND state='ACTIVE'",[id]);
   assert.equal(row.rowCount,1);assert.equal(attempt.rowCount,1);
   return {assessment_id:id,tenant_id:TENANT,claim_token:row.rows[0].claim_token as string,
    claim_generation:Number(row.rows[0].claim_generation),attempt_id:attempt.rows[0].id as string} satisfies WorkerClaim;
  });
  const stopped=exitChild(original);original.kill("SIGTERM");
  const outcome=await stopped;
  assert.equal(outcome.code,75,"blocked real worker must be forcibly stopped by its drain deadline");
  assert.equal(outcome.signal,null);assert(outcome.elapsedMs<2400);
  const before=await snapshot(id);assert.equal(before.reports,0);
  // Advance the disposable database's lease expiration, never forge the
  // claim_token or generation: the successor must use the real claim API.
  await withWorkerTenant(TENANT,tx=>tx.query(
   "UPDATE api_queue.api_assessment_queue SET locked_until=clock_timestamp()-interval '1 second' WHERE assessment_id=$1 AND claim_generation=$2",
   [id,lease.claim_generation]));
  const successor=spawnWorker();
  try{
   await stage(successor,"READY");
   let good=false;
   for(let i=0;i<80;i++){
    const state=await snapshot(id);
    if(state.status==="COMPLETED"){good=true;break;}
    await new Promise(resolve=>setTimeout(resolve,100));
   }
   assert(good,"new genuine OS worker must resume abandoned job");
   const exit=exitChild(successor);successor.kill("SIGTERM");
   const result=await exit;assert.equal(result.code,0);
  }finally{if(successor.exitCode===null)successor.kill("SIGKILL");}
  assert.equal(await renewWorkerClaim(lease),false);
  assert.equal(await releaseUnstartedWorkerClaim(lease),false);
  const finished=await snapshot(id);
  assert.equal(finished.status,"COMPLETED");assert.equal(finished.reports,1);
  assert.equal(finished.ledger,0,"offline synthetic work never settles commercial meter");
  assert.equal(finished.attempts.length,2);
  assert.deepEqual(finished.attempts.map(x=>x.state),["LOST","COMPLETED"]);
 }finally{if(original.exitCode===null)original.kill("SIGKILL");}
});
