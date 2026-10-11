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
  assert(observed.some(x=>x.kind==="WORKER_TERMINAL"&&x.classification==="VALIDATION"),JSON.stringify(observed));
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


test("Phase14 C8 every allowed diagnostic kind redacts hostile secrets, untrusted input and production output",()=>{
 const kinds=["HTTP_REJECTED","HTTP_COMPLETED","ASSESSMENT_ADMISSION","QUEUE_CLAIM",
  "LEASE_RENEWAL","WORKER_RETRY","WORKER_TERMINAL","DB_CONTENTION","RESOURCE_REJECTED",
  "REPORT_RENDER","REPORT_FINALIZED","METER_RESERVATION","METER_SETTLEMENT","METER_EXPIRY",
  "METER_CORRECTION","METER_RECONCILIATION","METER_ENTITLEMENT","ASSESSMENT_TRANSITION",
  "WORKER_SHUTDOWN","QA_DELIVERY"] as const;
 const classifications=["AUTH","VALIDATION","CAPACITY","TIMEOUT","CONFLICT","INTERNAL",
  "OK","STALE","RETRY","EXHAUSTED"] as const;
 const forbidden=["s3cr3t","Authorization","https://customer.internal",
  "BEARER_PAYLOAD","rawTenant","evidenceJson","sdkRefreshToken"];
 const injected="Authorization: Bearer s3cr3t https://customer.internal BEARER_PAYLOAD";
 const old={node:process.env.NODE_ENV,flag:process.env.SYNTHETIC_AUTH_ENABLED,
  diag:process.env.API_FAMILY_DIAGNOSTICS};
 const original=process.stderr.write,emitted:string[]=[];
 process.stderr.write=((chunk:unknown)=>{emitted.push(String(chunk));return true;}) as typeof process.stderr.write;
 try{
  process.env.NODE_ENV="test";process.env.SYNTHETIC_AUTH_ENABLED="true";
  process.env.API_FAMILY_DIAGNOSTICS="true";
  for(const [i,kind] of kinds.entries()){
   const input=Object.assign({kind,classification:classifications[i%classifications.length]!,
    statusCode:409,requestId:injected,durationMs:i+0.5,queueWaitMs:i,
    attempt:i,feature:injected,state:injected},
    {authorization:injected,rawTenant:injected,evidenceJson:injected,
     sdkRefreshToken:injected,targetUrl:injected,stack:injected});
   const safe=makeDiagnostic(input);
   assert.equal(safe.kind,kind);
   assert.equal(safe.requestId,null);
   assert.equal(safe.feature,null);
   assert.equal(safe.state,null);
   assert(Number.isFinite(safe.durationMs));
   emitDiagnostic(input);
  }
  assert.equal(emitted.length,kinds.length);
  const output=emitted.join("");
  for(const secret of forbidden)assert(!output.includes(secret),"leak: "+secret);
  for(const line of emitted){
   assert(line.startsWith("API_FAMILY_DIAGNOSTIC "));
   const item=JSON.parse(line.slice(22)) as {schemaVersion:string;requestId:null};
   assert.equal(item.schemaVersion,"api-family-diagnostic-v1");
   assert.equal(item.requestId,null);
   assert.deepEqual(Object.keys(item).sort(),Object.keys(makeDiagnostic({
    kind:"WORKER_SHUTDOWN",classification:"OK",statusCode:200})).sort());
  }
  process.env.NODE_ENV="production";emitDiagnostic({
   kind:"WORKER_SHUTDOWN",classification:"INTERNAL",statusCode:500,requestId:injected});
  process.env.NODE_ENV="test";process.env.SYNTHETIC_AUTH_ENABLED="false";
  emitDiagnostic({kind:"WORKER_SHUTDOWN",classification:"INTERNAL",statusCode:500});
  assert.equal(emitted.length,kinds.length,"production or unauthorized test process must not emit");
  console.log("PHASE14_C8_ALL_KIND_REDACTION_PASS "+JSON.stringify({kinds:kinds.length,
   attemptedSecretFields:7,untrustedValuesDropped:true,productionEmissions:0,externalTelemetry:false}));
 }finally{
  process.stderr.write=original;
  for(const [k,v] of [["NODE_ENV",old.node],["SYNTHETIC_AUTH_ENABLED",old.flag],
   ["API_FAMILY_DIAGNOSTICS",old.diag]] as const){
   if(v===undefined)delete process.env[k];else process.env[k]=v;
  }
 }
});
