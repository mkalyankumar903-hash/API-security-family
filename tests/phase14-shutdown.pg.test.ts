/** GitHub-hosted real worker SIGTERM, bounded forced deadline and database recovery. */
import {test,after} from "node:test";
import assert from "node:assert/strict";
import {randomUUID} from "node:crypto";
import {spawn,type ChildProcess} from "node:child_process";
import {performance} from "node:perf_hooks";
import {readFileSync} from "node:fs";
import {processOneJob} from "../packages/worker/src/index.js";
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
   ...(mode==="active-pt"?{PHASE14_TEST_ACTIVE_PT_BARRIER:"stalled"}:mode?{PHASE14_TEST_CLAIM_BARRIER:mode}:{})},
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
  const ready=stage(child,"READY"),claiming=stage(child,"PHASE14_CLAIM_HELD");
  await ready;const claimed=await claiming;
  assert.equal(claimed.assessmentId,id);
  const ended=exitChild(child);child.kill("SIGTERM");
  const exit=await ended;assert.deepEqual([exit.code,exit.signal],[0,null]);assert(exit.elapsedMs<3000);
  const db=await snapshot(id);
  assert.equal(db.status,"PROCESSING");
  assert.equal(db.reports,0);assert.equal(db.ledger,0);
  assert.equal(db.attempts[0].state,"LOST");
  // Terminally cancel this intentionally unstarted fixture so the following
  // real stalled-worker test can only claim its own fresh eligible job.
  const app=await makeApp();
  try{
   const cancel=await app.inject({method:"POST",url:"/v1/assessments/"+id+"/cancel",
    payload:{},headers:{authorization:"Bearer local-test-token-alpha"}});
   assert.equal(cancel.statusCode,200,cancel.body);
  }finally{await app.close();}
 }finally{if(child.exitCode===null)child.kill("SIGKILL");}
});
test("Phase14 real blocked worker exceeds bounded deadline then fresh worker recovers fenced PostgreSQL claim",async()=>{
 const id=await newJob(),original=spawnWorker("stalled");
 try{
  const initialReady=stage(original,"READY"),initialClaim=stage(original,"PHASE14_CLAIM_HELD");
  await initialReady;const held=await initialClaim;assert.equal(held.assessmentId,id);
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

test("Phase14 A2 genuine SIGTERM during committed governed PT evaluation; fenced resume publishes exactly once",async()=>{
 const fixture=readFileSync(new URL("../fixtures/phase07-security.openapi.json",import.meta.url),"utf8");
 const app=await makeApp();
 const call=async(method:"GET"|"POST",url:string,payload?:object,key?:string,authority=false)=>{
  const reply=await app.inject({method,url,payload,headers:{
   authorization:"Bearer local-test-token-alpha",...(key?{"idempotency-key":key}:{}),
   ...(authority?{"x-pt-authority-key":process.env.PT_TEST_AUTHORITY_KEY??""}:{})
  }});
  assert(reply.statusCode>=200&&reply.statusCode<300,reply.body);
  return reply.json() as Record<string,unknown>;
 };
 let id="",pt="";
 try{
  const t=await call("POST","/v1/targets",{name:"Active governed SIGTERM "+randomUUID().slice(0,8),
   environment:"SYNTHETIC",baseUrl:"https://active-pt-"+randomUUID().slice(0,8)+".fixture.invalid"});
  const tid=t.id as string;
  const imp=await call("POST","/v2/targets/"+tid+"/specifications/imports",
   {filename:"phase07-security.openapi.json",content:fixture},"active-spec-"+randomUUID());
  const sid=imp.specificationId as string;
  const ops=await call("GET","/v2/specifications/"+sid+"/operations?limit=100") as unknown as {key:string;method:string;path:string}[];
  const keys=["/pt/account","/pt/resources/bob","/pt/admin","/pt/confidential"]
   .map(path=>ops.find(op=>op.path===path&&op.method==="GET")?.key);
  assert(keys.every(Boolean));
  const scope=await call("POST","/v6/pt/targets/"+tid+"/scopes",{
   specificationId:sid,operationKeys:keys,fixtureId:"pt-security-v1",exclusions:[],
   maxEvaluations:14,ratePerMinute:14,maxConcurrency:1,deadlineMs:30000,validityMinutes:15
  },"active-scope-"+randomUUID());
  const scopeId=scope.id as string;
  await call("POST","/v6/pt/scopes/"+scopeId+"/request-authorization",{});
  await call("POST","/v6/pt/test-authority/scopes/"+scopeId+"/issue",{},undefined,true);
  const preview=await call("GET","/v11/api-vapt/scopes/"+scopeId+"/preview?policyId=SYNTHETIC_PT_COMPLETE_SUPPORTED&profile=SECURE_BASELINE");
  assert.equal(preview.authorizationReady,true);
  const parent=await call("POST","/v11/api-vapt/assessments",{
   mode:"GOVERNED_SYNTHETIC",scopeId,policyId:"SYNTHETIC_PT_COMPLETE_SUPPORTED",profile:"SECURE_BASELINE"
  },"active-parent-"+randomUUID());
  id=parent.id as string;pt=parent.ptAssessmentId as string;
  assert.equal(await processOneJob(),true,"real offline child must finish before PT worker starts");
  const original=spawnWorker("active-pt");
  try{
   const ready=stage(original,"READY");
   const stageReached=stage(original,"PHASE14_ACTIVE_PT_EVALUATION_COMMITTED",12000);
   await ready;
   const committed=await stageReached;
   assert.equal(committed.assessmentId,pt,"real worker executed the governed child");
   const before=await withTenant(TENANT,async tx=>{
    const e=await tx.query("SELECT count(*)::int AS n FROM api_pt_detection_evaluations WHERE assessment_id=$1 AND state='CONSUMED'",[pt]);
    const r=await tx.query("SELECT count(*)::int AS n FROM api_pt9_reports WHERE assessment_id=$1",[pt]);
    const p=await tx.query("SELECT count(*)::int AS n FROM api_vapt11_reports WHERE parent_assessment_id=$1",[id]);
    return {consumed:e.rows[0].n,pt:r.rows[0].n,parent:p.rows[0].n};
   });
   assert.deepEqual(before,{consumed:1,pt:0,parent:0});
   const stop=exitChild(original);original.kill("SIGTERM");
   const end=await stop;
   assert.equal(end.code,75,"actual governed PT worker must exceed real bounded drain");
   assert.equal(end.signal,null);assert(end.elapsedMs<2400);
   const old=await withWorkerTenant(TENANT,async tx=>{
    const q=await tx.query("SELECT claim_token,claim_generation FROM api_queue.api_assessment_queue WHERE assessment_id=$1",[pt]);
    const a=await tx.query("SELECT id FROM api_worker_attempts WHERE assessment_id=$1 AND state='ACTIVE'",[pt]);
    assert.equal(q.rowCount,1);assert.equal(a.rowCount,1);
    return {tenant_id:TENANT,assessment_id:pt,claim_token:q.rows[0].claim_token as string,
     claim_generation:Number(q.rows[0].claim_generation),attempt_id:a.rows[0].id as string} satisfies WorkerClaim;
   });
   await withWorkerTenant(TENANT,tx=>tx.query(
    "UPDATE api_queue.api_assessment_queue SET locked_until=clock_timestamp()-interval '1 second' WHERE assessment_id=$1 AND claim_generation=$2",
    [pt,old.claim_generation]));
   const successor=spawnWorker();
   try{
    await stage(successor,"READY");
    let completed=false;
    for(let i=0;i<100;i++){
     const state=await withTenant(TENANT,tx=>tx.query(
      "SELECT status FROM api_assessments WHERE id=$1",[id]));
     if(state.rows[0]?.status==="COMPLETED"){completed=true;break;}
     await new Promise(resolve=>setTimeout(resolve,100)); // bounded polling only; IPC controls fault boundary
    }
    assert(completed,"successor OS process must complete governed child and parent");
    const ended=exitChild(successor);successor.kill("SIGTERM");
    assert.equal((await ended).code,0);
   }finally{if(successor.exitCode===null)successor.kill("SIGKILL");}
   assert.equal(await renewWorkerClaim(old),false);
   assert.equal(await releaseUnstartedWorkerClaim(old),false);
   const final=await withTenant(TENANT,async tx=>{
    const result=await tx.query("SELECT state,count(*)::int AS n FROM api_pt_detection_evaluations WHERE assessment_id=$1 GROUP BY state",[pt]);
    const proofs=await tx.query("SELECT count(*)::int AS n FROM api_pt9_reports WHERE assessment_id=$1",[pt]);
    const reports=await tx.query("SELECT count(*)::int AS n FROM api_vapt11_reports WHERE parent_assessment_id=$1",[id]);
    const attempts=await tx.query("SELECT state FROM api_worker_attempts WHERE assessment_id=$1 ORDER BY claim_generation",[pt]);
    return {states:result.rows,proofs:proofs.rows[0].n,reports:reports.rows[0].n,
     attempts:attempts.rows.map(x=>x.state)};
   });
   assert.deepEqual(final.states,[{state:"CONSUMED",n:14}]);
   assert.equal(final.proofs,1);assert.equal(final.reports,1);
   assert.deepEqual(final.attempts,["LOST","COMPLETED"]);
   const decision=await withTenant(TENANT,async tx=>{
    const codes=await tx.query("SELECT stage_id,code FROM api_pt9_decisions WHERE assessment_id=$1 ORDER BY created_at",[pt]);
    const stages=await tx.query("SELECT stage_id,status,evidence_fingerprint FROM api_pt9_stages WHERE assessment_id=$1 ORDER BY ordinal",[pt]);
    const attempts=await tx.query("SELECT kind,code FROM api_worker_events WHERE assessment_id=$1",[pt]);
    return {codes:codes.rows,stages:stages.rows,attempts:attempts.rows};
   });
   for(const code of ["STAGE_ADMITTED","LEASED_RECOVERY","STAGE_EVIDENCE_COMPLETED",
    "ORCHESTRATION_COMPLETED"]){
    assert(decision.codes.some(x=>x.code===code),"missing authoritative transition: "+code);
   }
   assert(decision.stages.every(x=>x.status==="COMPLETED"&&
    typeof x.evidence_fingerprint==="string"&&x.evidence_fingerprint.length===64));
   assert(decision.attempts.some(x=>x.kind==="TAKEOVER"));
   const replaced=await withTenant(TENANT,tx=>tx.query(
    "SELECT state,failure_code FROM api_worker_attempts WHERE assessment_id=$1 ORDER BY claim_generation LIMIT 1",[pt]));
   assert.equal(replaced.rows[0].state,"LOST");
   assert.equal(replaced.rows[0].failure_code,"LEASE_REPLACED");
   const report=await call("GET","/v11/api-vapt/assessments/"+id+"/report");
   assert.equal(report.verifiedFixed,false);
   assert.equal(report.customerRuntimeVerified,false);
   assert.equal(report.fullAuthorizedVaptCompleted,true);
   assert.equal((await app.inject({method:"GET",url:"/v11/api-vapt/assessments/"+id+"/report",
    headers:{authorization:"Bearer local-test-token-beta"}})).statusCode,409); // report unavailability is deliberately a non-disclosing 409
   console.log("PHASE14_ACTIVE_GOVERNED_PT_SIGTERM_RECOVERY_PASS "+JSON.stringify({
    firstConsumed:before.consumed,afterConsumed:final.states[0]!.n,ptReports:1,parentReports:1,
    oldGenerationDenied:true,productionAuthorization:false,customerNetworkRequests:0}));
  }finally{if(original.exitCode===null)original.kill("SIGKILL");}
 }finally{await app.close();}
});


test("Phase14 real OS governed PT: customer cancels after one committed evaluation while worker is paused",async()=>{
 const app=await makeApp(),fixture=readFileSync(new URL("../fixtures/phase07-security.openapi.json",import.meta.url),"utf8");
 const call=async(method:"GET"|"POST",url:string,payload?:object,key?:string,authority=false)=>{
  const response=await app.inject({method,url,payload,headers:{
   authorization:"Bearer local-test-token-alpha",
   ...(key?{"idempotency-key":key}:{}),
   ...(authority?{"x-pt-authority-key":process.env.PT_TEST_AUTHORITY_KEY??""}:{})}});
  assert(response.statusCode>=200&&response.statusCode<300,response.body);
  return response.json() as Record<string,unknown>;
 };
 try{
  const t=await call("POST","/v1/targets",{name:"Active customer cancel "+randomUUID().slice(0,8),
   environment:"SYNTHETIC",baseUrl:"https://oscancel-"+randomUUID().slice(0,8)+".fixture.invalid"});
  const target=t.id as string;
  const imported=await call("POST","/v2/targets/"+target+"/specifications/imports",
   {filename:"phase07-security.openapi.json",content:fixture},"oscancel-spec-"+randomUUID());
  const spec=imported.specificationId as string;
  const ops=await call("GET","/v2/specifications/"+spec+"/operations?limit=100") as unknown as
   {key:string;method:string;path:string}[];
  const operationKeys=["/pt/account","/pt/resources/bob","/pt/admin","/pt/confidential"].map(path=>
   ops.find(op=>op.path===path&&op.method==="GET")?.key);
  assert(operationKeys.every(Boolean));
  const created=await call("POST","/v6/pt/targets/"+target+"/scopes",{
   specificationId:spec,operationKeys,fixtureId:"pt-security-v1",exclusions:[],
   maxEvaluations:14,ratePerMinute:14,maxConcurrency:1,deadlineMs:30000,validityMinutes:15
  },"oscancel-scope-"+randomUUID());
  const scope=created.id as string;
  await call("POST","/v6/pt/scopes/"+scope+"/request-authorization",{});
  const permit=(await call("POST","/v6/pt/test-authority/scopes/"+scope+"/issue",{},undefined,true)).id as string;
  const parent=await call("POST","/v11/api-vapt/assessments",{
   mode:"GOVERNED_SYNTHETIC",scopeId:scope,
   policyId:"SYNTHETIC_PT_COMPLETE_SUPPORTED",profile:"SECURE_BASELINE"
  },"oscancel-parent-"+randomUUID());
  const id=parent.id as string,pt=parent.ptAssessmentId as string;
  assert.equal(await processOneJob(),true,"offline child must commit before governed execution");
  const original=spawnWorker("active-pt");
  try{
   const ready=stage(original,"READY"),consumed=stage(original,"PHASE14_ACTIVE_PT_EVALUATION_COMMITTED",12000);
   await ready;
   const marker=await consumed;
   assert.equal(marker.assessmentId,pt);
   const before=await withTenant(TENANT,async tx=>{
    const evaluations=await tx.query(
     "SELECT count(*)::int AS n FROM api_pt_detection_evaluations WHERE assessment_id=$1 AND state='CONSUMED'",[pt]);
    const reports=await tx.query("SELECT count(*)::int AS n FROM api_vapt11_reports WHERE parent_assessment_id=$1",[id]);
    return {consumed:evaluations.rows[0].n,reports:reports.rows[0].n};
   });
   assert.deepEqual(before,{consumed:1,reports:0});
   const previous=await withWorkerTenant(TENANT,async tx=>{
    const queue=await tx.query("SELECT claim_token,claim_generation FROM api_queue.api_assessment_queue WHERE assessment_id=$1",[pt]);
    const attempts=await tx.query("SELECT id FROM api_worker_attempts WHERE assessment_id=$1 AND state='ACTIVE'",[pt]);
    assert.equal(queue.rowCount,1);assert.equal(attempts.rowCount,1);
    return {tenant_id:TENANT,assessment_id:pt,
     claim_token:queue.rows[0].claim_token as string,
     claim_generation:Number(queue.rows[0].claim_generation),
     attempt_id:attempts.rows[0].id as string} satisfies WorkerClaim;
   });
   const cancel=await call("POST","/v11/api-vapt/assessments/"+id+"/cancel",{});
   assert.equal(cancel.status,"CANCELLED");
   const stopped=exitChild(original);original.kill("SIGTERM");
   const outcome=await stopped;assert.equal(outcome.code,75);
   assert(outcome.elapsedMs<2400,"actual OS-process stop must stay bounded");
   assert.equal(await renewWorkerClaim(previous),false);
   assert.equal(await releaseUnstartedWorkerClaim(previous),false);
   // Finalize the stale worker's attempt from durable SQL only, not a fake successful job.
   await finishWorkerAttempt(previous);
   const snapshot=await withTenant(TENANT,async tx=>{
    const state=await tx.query("SELECT status FROM api_assessments WHERE id=ANY($1::uuid[]) ORDER BY id",[[id,pt]]);
    const receipts=await tx.query("SELECT state FROM api_pt_detection_evaluations WHERE assessment_id=$1",[pt]);
    const parentReports=await tx.query("SELECT count(*)::int AS n FROM api_vapt11_reports WHERE parent_assessment_id=$1",[id]);
    const ptReports=await tx.query("SELECT count(*)::int AS n FROM api_pt9_reports WHERE assessment_id=$1",[pt]);
    const attempts=await tx.query("SELECT state FROM api_worker_attempts WHERE assessment_id=$1 ORDER BY claim_generation",[pt]);
    const permitRow=await tx.query("SELECT consumed,reserved FROM api_pt_permits WHERE id=$1",[permit]);
    return {states:state.rows.map(x=>x.status),consumed:receipts.rows.filter(x=>x.state==="CONSUMED").length,
     parentReports:parentReports.rows[0].n,ptReports:ptReports.rows[0].n,
     attempts:attempts.rows.map(x=>x.state),permit:permitRow.rows[0]};
   });
   assert.deepEqual(snapshot.states,["CANCELLED","CANCELLED"]);
   assert.equal(snapshot.consumed,1);assert.equal(snapshot.parentReports,0);
   assert.equal(snapshot.ptReports,0);
   assert.equal(snapshot.permit.consumed,1);
   assert.equal(snapshot.permit.reserved,0);
   assert.deepEqual(snapshot.attempts,["CANCELLED"]);
   assert.equal((await app.inject({method:"GET",url:"/v11/api-vapt/assessments/"+id+"/report",
    headers:{authorization:"Bearer local-test-token-alpha"}})).statusCode,409);
   console.log("PHASE14_ACTIVE_OS_CUSTOMER_CANCEL_PASS "+JSON.stringify({
    firstConsumed:1,afterConsumed:1,parentReports:0,ptReports:0,oldLeaseFenced:true,
    terminal:"CANCELLED",noExternalTargets:true,verifiedFixed:false}));
  }finally{if(original.exitCode===null&&original.signalCode===null)original.kill("SIGKILL");}
 }finally{await app.close();}
});
