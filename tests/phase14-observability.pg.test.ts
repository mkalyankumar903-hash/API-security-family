/** Actual worker→PostgreSQL→diagnostic integration, no simulated engine outcome. */
import {test,after} from "node:test";
import assert from "node:assert/strict";
import {randomUUID} from "node:crypto";
import {makeApp} from "../packages/service/src/app.js";
import {migrate,withWorkerTenant,withTenant,closeDatabase} from "../packages/database/src/index.js";
import {processOneJob} from "../packages/worker/src/index.js";
import {makeDiagnostic,emitDiagnostic} from "../packages/contracts/src/operational-diagnostics-v14.js";
const A="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const SPEC=JSON.stringify({openapi:"3.1.0",info:{title:"Phase14 worker",version:"1.0.0"},paths:{
 "/health":{get:{responses:{"200":{description:"synthetic"}}}}}});
after(async()=>{await closeDatabase();});
test("Phase14 real poisoned worker emits only redacted operational events and persists failed quarantine",async()=>{
 await migrate();
 const app=await makeApp();
 const former={diagnostics:process.env.API_FAMILY_DIAGNOSTICS,node:process.env.NODE_ENV,
  synthetic:process.env.SYNTHETIC_AUTH_ENABLED};
 const orig=process.stderr.write;
 const lines:string[]=[];
 process.env.NODE_ENV="test";process.env.SYNTHETIC_AUTH_ENABLED="true";
 process.env.API_FAMILY_DIAGNOSTICS="true";
 process.stderr.write=((chunk:unknown)=>{lines.push(String(chunk));return true;}) as typeof process.stderr.write;
 try{
  const api=(url:string,data:object,key?:string)=>app.inject({method:"POST",url,payload:data,headers:{
   authorization:"Bearer local-test-token-alpha",...(key?{"idempotency-key":key}:{})}});
  const t=await api("/v1/targets",{name:"Telemetry "+randomUUID().slice(0,8),
   environment:"SYNTHETIC",baseUrl:"https://telemetry-"+randomUUID()+".fixture.invalid"});
  assert.equal(t.statusCode,201,t.body);
  const tid=t.json().id as string;
  const spec=await api("/v1/targets/"+tid+"/specifications",{filename:"observed.json",content:SPEC});
  assert.equal(spec.statusCode,201,spec.body);
  const job=await api("/v1/targets/"+tid+"/assessments",{specificationId:spec.json().id,mode:"SPEC_ONLY"},
   "telemetry-"+randomUUID());
  assert.equal(job.statusCode,201,job.body);
  const id=job.json().id as string;
  await withWorkerTenant(A,tx=>tx.query(
   "UPDATE api_assessments SET engine_version='inventory-v1',inventory_version=1,inventory_raw_fingerprint=$2,inventory_fingerprint=$3 WHERE id=$1 AND status='QUEUED'",
   [id,"a".repeat(64),"b".repeat(64)]));
  assert.equal(await processOneJob(),true);
  const db=await withTenant(A,async tx=>{
   const assessments=await tx.query("SELECT status FROM api_assessments WHERE id=$1",[id]);
   const quarantined=await tx.query("SELECT reason_code FROM api_worker_quarantine WHERE assessment_id=$1",[id]);
   const reports=await tx.query("SELECT count(*)::int AS n FROM api_reports WHERE assessment_id=$1",[id]);
   return {status:assessments.rows[0].status,reason:quarantined.rows[0].reason_code,reports:reports.rows[0].n};
  });
  assert.deepEqual(db,{status:"FAILED",reason:"INVENTORY_SNAPSHOT_MISMATCH",reports:0});
  const observed=lines.filter(x=>x.startsWith("API_FAMILY_DIAGNOSTIC ")).map(x=>JSON.parse(x.slice(22)) as {kind:string;classification:string;queueWaitMs:number|null});
  assert(observed.some(x=>x.kind==="QUEUE_CLAIM"&&x.queueWaitMs!==null));
  assert(observed.some(x=>x.kind==="WORKER_TERMINAL"&&x.classification==="VALIDATION"));
  assert(observed.every(x=>typeof x.kind==="string"));
  assert(!lines.join("").includes(id));
  assert(!lines.join("").includes(A));
  assert(!lines.join("").includes("INVENTORY_SNAPSHOT_MISMATCH"));
 }finally{
  process.stderr.write=orig;
  for(const [key,value] of [["API_FAMILY_DIAGNOSTICS",former.diagnostics],["NODE_ENV",former.node],
   ["SYNTHETIC_AUTH_ENABLED",former.synthetic]] as const){
   if(value===undefined)delete process.env[key];else process.env[key]=value;
  }
  await app.close();
 }
});
test("Phase14 adversarial diagnostics bound unknown enum, giant IDs, secrets, invalid numeric inputs",()=>{
 const secret="Authorization: Bearer hidden_secret\\n";
 const obj=Object.assign({kind:"HTTP_REJECTED" as const,classification:"INTERNAL" as const,
  requestId:secret+"x".repeat(200),durationMs:-3,queueWaitMs:Infinity,attempt:NaN,statusCode:9999},
  {token:secret,error:{message:secret},targetUrl:"https://secret.invalid"});
 const record=makeDiagnostic(obj);
 const serialized=JSON.stringify(record);
 for(const forbidden of ["Authorization","hidden_secret","secret.invalid","targetUrl","tenantId"]){
  assert(!serialized.includes(forbidden));
 }
 assert.deepEqual([record.requestId,record.durationMs,record.queueWaitMs,record.attempt],[null,null,null,null]);
 assert.equal(record.statusCode,500);
 const previous={node:process.env.NODE_ENV,flag:process.env.SYNTHETIC_AUTH_ENABLED,
  telemetry:process.env.API_FAMILY_DIAGNOSTICS};
 const orig=process.stderr.write;let calls=0;
 process.stderr.write=((_chunk:unknown)=>{calls++;return true;}) as typeof process.stderr.write;
 try{
  process.env.NODE_ENV="production";process.env.SYNTHETIC_AUTH_ENABLED="true";
  process.env.API_FAMILY_DIAGNOSTICS="true";emitDiagnostic(obj);assert.equal(calls,0);
  process.env.NODE_ENV="test";process.env.SYNTHETIC_AUTH_ENABLED="false";
  emitDiagnostic(obj);assert.equal(calls,0);
  process.env.SYNTHETIC_AUTH_ENABLED="true";emitDiagnostic(obj);assert.equal(calls,1);
 }finally{
  process.stderr.write=orig;
  for(const [key,value] of [["NODE_ENV",previous.node],["SYNTHETIC_AUTH_ENABLED",previous.flag],
   ["API_FAMILY_DIAGNOSTICS",previous.telemetry]] as const){
   if(value===undefined)delete process.env[key];else process.env[key]=value;
  }
 }
});
