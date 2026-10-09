import {test,after} from "node:test";
import assert from "node:assert/strict";
import {randomUUID} from "node:crypto";
import {migrate,claimJob,renewWorkerClaim,withTenant,withWorkerTenant,closeDatabase} from "../packages/database/src/index.js";
import {processOneJob} from "../packages/worker/src/index.js";
import {scheduleConservativeRetry} from "../packages/worker/src/safety-retry.js";
import {makeApp} from "../packages/service/src/app.js";
const A="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const SPEC=JSON.stringify({openapi:"3.1.0",info:{title:"Concurrency negative",version:"1.0.0"},
 paths:{"/health":{get:{responses:{"200":{description:"Synthetic"}}}}}});
after(async()=>{await closeDatabase();});
test("Phase10 independent worker race: poison integrity cannot become a report or survive concurrent claims",async()=>{
 await migrate();const app=await makeApp();
 try{
  const token="local-test-token-alpha";
  const api=(method:"POST"|"GET",path:string,data?:object,key?:string)=>app.inject({
   method,url:path,payload:data,headers:{authorization:"Bearer "+token,...(key?{"idempotency-key":key}:{})}});
  const target=await api("POST","/v1/targets",{name:"Poison "+randomUUID().slice(0,7),
   environment:"SYNTHETIC",baseUrl:"https://poison-"+randomUUID()+".fixture.invalid"});
  assert.equal(target.statusCode,201,target.body);
  const tid=target.json().id as string;
  const imported=await api("POST","/v1/targets/"+tid+"/specifications",{filename:"poison.json",content:SPEC});
  assert.equal(imported.statusCode,201,imported.body);
  const job=await api("POST","/v1/targets/"+tid+"/assessments",
   {specificationId:imported.json().id,mode:"SPEC_ONLY"},"poison-"+randomUUID());
  assert.equal(job.statusCode,201,job.body);
  const id=job.json().id as string;
  // This valid historical inventory engine identifier with missing signed
  // immutable inventory is a deliberately poisoned queue payload.
  await withWorkerTenant(A,tx=>tx.query(
   "UPDATE api_assessments SET engine_version='inventory-v1' WHERE id=$1 AND status='QUEUED'",[id]));
  const [a,b,c]=await Promise.all([processOneJob(),processOneJob(),processOneJob()]);
  assert.equal([a,b,c].filter(Boolean).length,1,"one independently claimed worker may terminalize poisoned job");
  const state=await api("GET","/v1/assessments/"+id);
  assert.equal(state.json().status,"FAILED",state.body);
  const observed=await withTenant(A,async tx=>{
   const reports=await tx.query("SELECT count(*)::int AS n FROM api_reports WHERE assessment_id=$1",[id]);
   const quarantine=await tx.query("SELECT reason_code FROM api_worker_quarantine WHERE assessment_id=$1",[id]);
   const attempts=await tx.query("SELECT state FROM api_worker_attempts WHERE assessment_id=$1",[id]);
   return {reports:reports.rows[0].n,quarantine:quarantine.rows[0],attempts:attempts.rows};
  });
  assert.equal(observed.reports,0);
  assert.equal(observed.quarantine.reason_code,"INVENTORY_SNAPSHOT_MISMATCH");
  assert.equal(observed.attempts.length,1);
  assert.equal(observed.attempts[0].state,"FAILED");
  const q=await withWorkerTenant(A,tx=>tx.query("SELECT 1 FROM api_queue.api_assessment_queue WHERE assessment_id=$1",[id]));
  assert.equal(q.rowCount,0);
  assert.equal(await claimJob(),null,"poison cannot reenter queue");
  const safe=await api("GET","/v10/workers/assessments/"+id+"/execution");
  assert.equal(safe.statusCode,200,safe.body);
  assert.equal(safe.json().quarantine.reason_code,"INVENTORY_SNAPSHOT_MISMATCH");
 }finally{await app.close();}
});

test("Phase10 real PostgreSQL races: renewal or retry versus cancellation never publishes success",async()=>{
 await migrate();const app=await makeApp();
 const api=(method:"POST"|"GET",path:string,data?:object,key?:string)=>app.inject({
  method,url:path,payload:data,headers:{authorization:"Bearer local-test-token-alpha",
   ...(key?{"idempotency-key":key}:{})}});
 try{
  const target=await api("POST","/v1/targets",{name:"Retry cancellation "+randomUUID().slice(0,6),
   environment:"SYNTHETIC",baseUrl:"https://cancel-race-"+randomUUID()+".fixture.invalid"});
  assert.equal(target.statusCode,201,target.body);const tid=target.json().id as string;
  const spec=await api("POST","/v1/targets/"+tid+"/specifications",{filename:"cancelrace.json",content:SPEC});
  assert.equal(spec.statusCode,201,spec.body);
  for(const mode of ["heartbeat","retry"] as const){
   const job=await api("POST","/v1/targets/"+tid+"/assessments",
    {specificationId:spec.json().id,mode:"SPEC_ONLY"},"cancel-race-"+randomUUID());
   assert.equal(job.statusCode,201,job.body);const jid=job.json().id as string;
   const claim=await claimJob();assert.equal(claim?.assessment_id,jid);
   // Independent Fastify application and worker PostgreSQL sessions race.
   const [operation,cancel]=await Promise.all([
    mode==="heartbeat"?renewWorkerClaim(claim!):scheduleConservativeRetry(claim!,{code:"08006"}),
    api("POST","/v1/assessments/"+jid+"/cancel",{})
   ]);
   assert.equal(cancel.statusCode,200,cancel.body);
   if(mode==="heartbeat")assert.equal(typeof operation,"boolean");
   else assert.ok(["STALE","RETRY_SCHEDULED"].includes(operation as string));
   assert.equal(await renewWorkerClaim(claim!),false,"terminal cancellation always fences stale heartbeat");
   const status=await api("GET","/v1/assessments/"+jid);
   assert.equal(status.json().status,"CANCELLED");
   const rows=await withTenant(A,tx=>tx.query("SELECT count(*)::int AS n FROM api_reports WHERE assessment_id=$1",[jid]));
   assert.equal(rows.rows[0].n,0);
   const queue=await withWorkerTenant(A,tx=>tx.query("SELECT count(*)::int AS n FROM api_queue.api_assessment_queue WHERE assessment_id=$1",[jid]));
   assert.equal(queue.rows[0].n,0,"cancelled delayed retry never revives queue");
  }
 }finally{await app.close();}
});
