/** Phase14 final security: actual governed PT worker evaluation and HTTP cancellation/revocation boundaries.
 * Real Fastify HTTP transport, private PostgreSQL16 worker leases and consumed synthetic receipts only.
 */
import {test,after} from "node:test";
import assert from "node:assert/strict";
import {randomUUID} from "node:crypto";
import {readFileSync} from "node:fs";
import {connect} from "node:net";
import {makeApp} from "../packages/service/src/app.js";
import {migrate,withTenant,withWorkerTenant,claimJob,finishWorkerAttempt,closeDatabase} from "../packages/database/src/index.js";
import {processPtOrchestrationJob} from "../packages/worker/src/pt-orchestrator.js";
const A="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",B="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const SPEC=readFileSync(new URL("../fixtures/phase07-security.openapi.json",import.meta.url),"utf8");
after(async()=>{await closeDatabase();});
function barrier(){
 let ready!:()=>void,release!:()=>void;
 return {entered:new Promise<void>(r=>{ready=r}),resume:new Promise<void>(r=>{release=r}),ready:()=>ready(),release:()=>release()};
}
test("Phase14 real governed PT: user cancellation after committed evaluation and independent mid-execution TCP disconnect",async()=>{
 await migrate();
 const app=await makeApp();
 const headers={authorization:"Bearer local-test-token-alpha"};
 const call=(method:"GET"|"POST",url:string,body?:object,key?:string,authority=false)=>app.inject({
  method,url,payload:body,headers:{...headers,...(key?{"idempotency-key":key}:{}),
   ...(authority?{"x-pt-authority-key":process.env.PT_TEST_AUTHORITY_KEY??""}:{})}});
 const requireCode=(res:{statusCode:number;body:string;json:()=>Record<string,unknown>},code:number)=>{
  assert.equal(res.statusCode,code,res.body);return res.json();
 };
 const scopeAndParent=async()=>{
  const t=requireCode(await call("POST","/v1/targets",{
   name:"Phase14 active cancel "+randomUUID().slice(0,8),environment:"SYNTHETIC",
   baseUrl:"https://pt-cancel-"+randomUUID().slice(0,8)+".fixture.invalid"}),201);
  const target=t.id as string;
  const imported=requireCode(await call("POST","/v2/targets/"+target+"/specifications/imports",{
   filename:"phase07-security.openapi.json",content:SPEC},"pt-cancel-spec-"+randomUUID()),201);
  const specification=imported.specificationId as string;
  const ops=requireCode(await call("GET","/v2/specifications/"+specification+"/operations?limit=100"),200) as unknown as {key:string;path:string;method:string}[];
  const keys=["/pt/account","/pt/resources/bob","/pt/admin","/pt/confidential"].map(path=>
   ops.find(op=>op.path===path&&op.method==="GET")?.key);
  assert(keys.every(Boolean));
  const scope=requireCode(await call("POST","/v6/pt/targets/"+target+"/scopes",{
   specificationId:specification,operationKeys:keys,fixtureId:"pt-security-v1",exclusions:[],
   maxEvaluations:14,ratePerMinute:14,maxConcurrency:1,deadlineMs:30000,validityMinutes:15
  },"pt-cancel-scope-"+randomUUID()),201).id as string;
  requireCode(await call("POST","/v6/pt/scopes/"+scope+"/request-authorization",{}),201);
  const permit=requireCode(await call("POST","/v6/pt/test-authority/scopes/"+scope+"/issue",{},undefined,true),201).id as string;
  const run=requireCode(await call("POST","/v9/pt/scopes/"+scope+"/orchestrations",{
   policyId:"SYNTHETIC_PT_COMPLETE_SUPPORTED",profile:"SECURE_BASELINE"},"pt-cancel-run-"+randomUUID()),201);
  const id=run.id as string;
  const lease=await claimJob();
  assert.equal(lease?.assessment_id,id,"each scoped fixture must own the real queue claim");
  await withWorkerTenant(A,tx=>tx.query("UPDATE api_assessments SET status='PROCESSING' WHERE id=$1 AND status='QUEUED'",[id]));
  return {id,permit,scope,lease:lease!};
 };
 const snapshot=(id:string)=>withTenant(A,async tx=>{
  const a=await tx.query("SELECT status FROM api_assessments WHERE id=$1",[id]);
  const evals=await tx.query("SELECT state FROM api_pt_detection_evaluations WHERE assessment_id=$1 ORDER BY evaluation_key",[id]);
  const p=await tx.query("SELECT count(*)::int AS n FROM api_pt9_reports WHERE assessment_id=$1",[id]);
  const st=await tx.query("SELECT status FROM api_pt9_stages WHERE assessment_id=$1 ORDER BY ordinal",[id]);
  const tr=await tx.query("SELECT count(*)::int AS n FROM api_pt9_terminal WHERE assessment_id=$1",[id]);
  return {status:a.rows[0]?.status,consumed:evals.rows.filter(v=>v.state==="CONSUMED").length,
   reports:p.rows[0].n,stages:st.rows.map(v=>v.status),terminal:tr.rows[0].n};
 });
 try{
  const user=await scopeAndParent(),gate=barrier();
  const inFlight=processPtOrchestrationJob(A,user.id,user.lease.claim_token,{
   afterEvaluation:async count=>{if(count===1){gate.ready();await gate.resume;}}
  });
  await gate.entered; // true committed first synthetic evaluation, no timer
  const actual=await snapshot(user.id);
  assert.equal(actual.status,"PROCESSING");assert.equal(actual.consumed,1);assert.equal(actual.reports,0);
  // Disconnect an actual completed request on the wire while an unrelated worker remains in-flight.
  const address=new URL(await app.listen({host:"127.0.0.1",port:0}));
  const socket=connect({host:"127.0.0.1",port:Number(address.port)});
  socket.on("error",()=>{});
  await new Promise<void>((resolve,reject)=>{socket.once("connect",resolve);socket.once("error",reject)});
  const aborted=new Promise<void>(resolve=>socket.once("close",resolve));
  socket.write("GET /v9/pt/orchestrations/"+user.id+" HTTP/1.1\r\nHost: 127.0.0.1:"+address.port+
   "\r\nAuthorization: Bearer local-test-token-alpha\r\nConnection: keep-alive\r\n\r\n");
  socket.destroy();await aborted;
  assert.equal((await snapshot(user.id)).consumed,1,"lost read transport never rewinds committed execution");
  const cancel=requireCode(await call("POST","/v9/pt/orchestrations/"+user.id+"/cancel",{}),200);
  assert.equal(cancel.status,"CANCELLED");
  gate.release();await inFlight;await finishWorkerAttempt(user.lease);
  const cancelled=await snapshot(user.id);
  assert.equal(cancelled.status,"CANCELLED");assert.equal(cancelled.consumed,1);
  assert.equal(cancelled.reports,0);assert.equal(cancelled.terminal,1);
  assert(cancelled.stages.every(s=>["CANCELLED","COMPLETED"].includes(s)));
  assert.equal((await call("GET","/v9/pt/orchestrations/"+user.id+"/report")).statusCode,409);
  assert.equal((await call("GET","/v9/pt/orchestrations/"+user.id+"/report",undefined,undefined,false)).statusCode,409);
  const cross=await withTenant(B,tx=>tx.query("SELECT 1 FROM api_pt_detection_evaluations WHERE assessment_id=$1",[user.id]));
  assert.equal(cross.rowCount,0);
  const permitBefore=await withTenant(A,tx=>tx.query("SELECT consumed FROM api_pt_permits WHERE id=$1",[user.permit]));
  assert.equal(permitBefore.rows[0].consumed,1);
  assert.equal((await call("POST","/v9/pt/orchestrations/"+user.id+"/cancel",{})).statusCode,409);
  const recovery=await withTenant(A,tx=>tx.query("SELECT count(*)::int AS n FROM api_pt9_reports WHERE assessment_id=$1",[user.id]));
  assert.equal(recovery.rows[0].n,0);

  // Independent permitted-evaluation boundary: revocation after exactly one committed interaction.
  const revoked=await scopeAndParent(),revocationGate=barrier();
  const working=processPtOrchestrationJob(A,revoked.id,revoked.lease.claim_token,{
   afterEvaluation:async count=>{if(count===1){revocationGate.ready();await revocationGate.resume;}}
  });
  await revocationGate.entered;
  assert.equal((await snapshot(revoked.id)).consumed,1);
  requireCode(await call("POST","/v6/pt/test-authority/permits/"+revoked.permit+"/revoke",{},undefined,true),200);
  revocationGate.release();await working;await finishWorkerAttempt(revoked.lease);
  const denied=await snapshot(revoked.id);
  assert.notEqual(denied.status,"COMPLETED");assert.equal(denied.reports,0);
  assert.equal(denied.consumed,1,"a revoked permit never authorizes evaluation two");
  assert.equal((await call("GET","/v9/pt/orchestrations/"+revoked.id+"/report")).statusCode,409);
  assert.equal((await withTenant(A,tx=>tx.query(
   "SELECT revoked_at IS NOT NULL AS revoked FROM api_pt_permits WHERE id=$1",[revoked.permit]))).rows[0].revoked,true);
  console.log("PHASE14_ACTIVE_USER_CANCEL_REVOCATION_TRANSPORT_PASS "+JSON.stringify({
   customerCancelledAfterConsumed:1,cancelReports:0,revokedAfterConsumed:1,
   revokedReports:0,transportDisconnectedDuringActive:true,wrongTenantRows:0,
   customerNetworkRequests:0,verifiedFixed:false}));
 }finally{await app.close();}
});
