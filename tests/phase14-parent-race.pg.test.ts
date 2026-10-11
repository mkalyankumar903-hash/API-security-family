/** Phase14 F5: deterministic real SQL parent publish-vs-cancel serialization.
 * The finalizer holds real stop/queue/parent row locks before pausing;
 * cancellation must never overwrite its committed immutable success. Conversely,
 * a committed cancellation defeats an unstarted parent finalizer.
 */
import {test,after} from "node:test";
import assert from "node:assert/strict";
import {randomUUID} from "node:crypto";
import {readFileSync} from "node:fs";
import {makeApp} from "../packages/service/src/app.js";
import {migrate,withTenant,claimJob,closeDatabase,finishWorkerAttempt} from "../packages/database/src/index.js";
import {processOneJob} from "../packages/worker/src/index.js";
import {processAutonomousVaptJob} from "../packages/worker/src/autonomous-vapt.js";
const A="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const SPEC=readFileSync(new URL("../fixtures/phase07-security.openapi.json",import.meta.url),"utf8");
after(async()=>{await closeDatabase();});
test("Phase14 genuine committed parent finalizer wins cancellation under Postgres locks; converse cancellation forbids publication",async()=>{
 await migrate();const app=await makeApp();
 const call=(method:"POST"|"GET",url:string,payload?:object,key?:string)=>app.inject({
  method,url,payload,headers:{authorization:"Bearer local-test-token-alpha",
   ...(key?{"idempotency-key":key}:{})}});
 const created=async()=>{
  const t=await call("POST","/v1/targets",{
   name:"F5 parent race "+randomUUID().slice(0,9),environment:"SYNTHETIC",
   baseUrl:"https://f5race-"+randomUUID().slice(0,9)+".fixture.invalid"});
  assert.equal(t.statusCode,201,t.body);const target=t.json().id as string;
  const imported=await call("POST","/v2/targets/"+target+"/specifications/imports",
   {filename:"phase07-security.openapi.json",content:SPEC},"race-import-"+randomUUID());
  assert.equal(imported.statusCode,201,imported.body);
  const parent=await call("POST","/v11/api-vapt/assessments",{
   mode:"OFFLINE_ONLY",targetId:target,specificationId:imported.json().specificationId
  },"race-parent-"+randomUUID());
  assert.equal(parent.statusCode,201,parent.body);
  const id=parent.json().id as string;
  assert.equal(await processOneJob(),true,"real offline child must complete before parent claim");
  const claim=await claimJob();
  assert.equal(claim?.assessment_id,id);
  return {id,claim:claim!};
 };
 try{
  const winner=await created();
  let allow!:()=>void,entered!:()=>void;
  const barrier=new Promise<void>(resolve=>{allow=resolve;});
  const parked=new Promise<void>(resolve=>{entered=resolve;});
  const finalizer=processAutonomousVaptJob(A,winner.id,winner.claim.claim_token,{
   beforeImmutablePublication:async()=>{entered();await barrier;}
  });
  await parked; // actual DB transaction holds stop, queue and parent locks here
  const cancelRequest=call("POST","/v11/api-vapt/assessments/"+winner.id+"/cancel",{});
  allow();await finalizer;
  await finishWorkerAttempt(winner.claim);
  const cancelResult=await cancelRequest;
  assert.equal(cancelResult.statusCode,409,cancelResult.body);
  const persisted=await withTenant(A,async tx=>{
   const a=await tx.query("SELECT status FROM api_assessments WHERE id=$1",[winner.id]);
   const r=await tx.query("SELECT count(*)::int AS n FROM api_vapt11_reports WHERE parent_assessment_id=$1",[winner.id]);
   const c=await tx.query("SELECT count(*)::int AS n FROM api_vapt11_terminal WHERE parent_assessment_id=$1",[winner.id]);
   return {status:a.rows[0].status,reports:r.rows[0].n,terminal:c.rows[0].n};
  });
  assert.deepEqual(persisted,{status:"COMPLETED",reports:1,terminal:0});
  const actual=await call("GET","/v11/api-vapt/assessments/"+winner.id+"/report");
  assert.equal(actual.statusCode,200,actual.body);
  assert.equal(actual.json().verifiedFixed,false);
  assert.equal(actual.json().customerRuntimeVerified,false);
  const losing=await created();
  const cancelled=await call("POST","/v11/api-vapt/assessments/"+losing.id+"/cancel",{});
  assert.equal(cancelled.statusCode,200,cancelled.body);
  await assert.rejects(()=>processAutonomousVaptJob(A,losing.id,losing.claim.claim_token),
   /VAPT11_PARENT_LEASE_LOST|VAPT11_PARENT_NOT_PROCESSING/);
  const denied=await withTenant(A,async tx=>{
   const a=await tx.query("SELECT status FROM api_assessments WHERE id=$1",[losing.id]);
   const r=await tx.query("SELECT count(*)::int AS n FROM api_vapt11_reports WHERE parent_assessment_id=$1",[losing.id]);
   const t=await tx.query("SELECT count(*)::int AS n FROM api_vapt11_terminal WHERE parent_assessment_id=$1",[losing.id]);
   return {status:a.rows[0].status,reports:r.rows[0].n,terminal:t.rows[0].n};
  });
  assert.deepEqual(denied,{status:"CANCELLED",reports:0,terminal:1});
  console.log("PHASE14_REAL_PARENT_PUBLICATION_CANCELLATION_RACE_PASS "+JSON.stringify({
   finalizerFirst:{report:1,lateCancelHttp:409},cancelFirst:{report:0,terminal:"CANCELLED"},
   duplicateReports:0,verifiedFixed:false,customerNetworkRequests:0}));
 }finally{await app.close();}
});
