/** Phase14 E6: real PostgreSQL16, Fastify and private worker measurement. No customer network.
 * Cold and warm writes are explicitly separated; never describe a replay as first-write.
 */
import {test,after} from "node:test";
import assert from "node:assert/strict";
import {randomUUID,randomBytes,createHmac} from "node:crypto";
import {performance} from "node:perf_hooks";
import {readFileSync} from "node:fs";
import {makeApp} from "../packages/service/src/app.js";
import {migrate,withTenant,withWorkerTenant,claimJob,closeDatabase} from "../packages/database/src/index.js";
import {processOneJob} from "../packages/worker/src/index.js";
import {processAutonomousVaptJob} from "../packages/worker/src/autonomous-vapt.js";
import {V13} from "../packages/contracts/src/commercial-v13.js";
import {ingestSyntheticEntitlement,reserveFeatureObservation,settleFeatureObservation,reconcilePending,projection} from "../packages/service/src/phase13.js";
const A="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",B="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const SPEC=readFileSync(new URL("../fixtures/phase07-security.openapi.json",import.meta.url),"utf8");
const paths=["/pt/account","/pt/resources/bob","/pt/admin","/pt/confidential"];
const feature="OFFLINE_API_ASSESSMENT_COMPLETED";
type API={statusCode:number;body:string;json:()=>Record<string,unknown>};
type Point={name:string;durations:number[];warmup:number;errors:number;heapBefore:number;cpuBefore:NodeJS.CpuUsage;details:string};
const series=new Map<string,Point>();
function timed(name:string,details:string,warmup=2){
 let row=series.get(name);if(!row){
  row={name,durations:[],warmup,errors:0,heapBefore:process.memoryUsage().heapUsed,cpuBefore:process.cpuUsage(),details};
  series.set(name,row);
 }
 return async<T>(action:()=>Promise<T>,iteration:number):Promise<T>=>{
  const start=performance.now();
  try{
   const value=await action();
   const ms=performance.now()-start;
   assert(Number.isFinite(ms)&&ms>=0,"finite genuine operation timing");
   if(iteration>=row!.warmup)row!.durations.push(ms);
   return value;
  }catch(error){row!.errors++;throw error;}
 };
}
function emit(){
 for(const row of series.values()){
  const v=[...row.durations].sort((a,b)=>a-b);
  assert(v.length>=8,"at least 8 observed samples plus explicit warmups for "+row.name);
  assert.equal(row.errors,0,row.name+" may not hide failures");
  const cpu=process.cpuUsage(row.cpuBefore);
  console.log("PHASE14_E6_REAL_SUBSYSTEM "+JSON.stringify({
   operation:row.name,source:row.details,warmup:row.warmup,samples:v.length,concurrency:1,
   medianMs:Number(v[Math.floor((v.length-1)/2)]!.toFixed(3)),
   p95Ms:Number(v[Math.ceil(v.length*.95)-1]!.toFixed(3)),
   errors:row.errors,heapDeltaBytes:process.memoryUsage().heapUsed-row.heapBefore,
   cpuUserMicros:cpu.user,cpuSystemMicros:cpu.system,
   environment:"GitHub-hosted Node22 PostgreSQL16 disposable synthetic fixture",
   regressionGate:"zero error/zero bad state/finite duration; hard p95-ms threshold NOT statistically defensible with shared hosted runner; compare distribution across exact runner environments",
   productionSLO:false,customerNetworkRequests:0}));
 }
}
after(async()=>{await closeDatabase();});
test("Phase14 E6 actual signed governed PT, planner, queue, parent composition, retrieval, recovery, cancellation and first-write meters",async()=>{
 await migrate();
 const app=await makeApp();
 const call=(method:"GET"|"POST",url:string,payload?:unknown,key?:string,authority=false,token="local-test-token-alpha")=>
  app.inject({method,url,payload:payload as object|undefined,headers:{
   authorization:"Bearer "+token,...(key?{"idempotency-key":key}:{}),
   ...(authority?{"x-pt-authority-key":process.env.PT_TEST_AUTHORITY_KEY??""}:{})
  }}) as Promise<API>;
 const ok=(v:API,code:number)=>{assert.equal(v.statusCode,code,v.body);return v.json();};
 const samples=10;
 try{
  const t=ok(await call("POST","/v1/targets",{name:"E6 "+randomUUID().slice(0,8),
   environment:"SYNTHETIC",baseUrl:"https://phase14-e6-"+randomUUID().slice(0,8)+".fixture.invalid"}),201);
  const tid=t.id as string;
  const imp=ok(await call("POST","/v2/targets/"+tid+"/specifications/imports",
   {filename:"phase07-security.openapi.json",content:SPEC},"e6-import-"+randomUUID()),201);
  const sid=imp.specificationId as string;
  const ops=ok(await call("GET","/v2/specifications/"+sid+"/operations?limit=100"),200) as unknown as {key:string;method:string;path:string}[];
  const keys=paths.map(path=>ops.find(v=>v.path===path&&v.method==="GET")?.key);
  assert(keys.every(Boolean));
  const reports:string[]=[];
  for(let i=0;i<samples;i++){
   const scope=ok(await call("POST","/v6/pt/targets/"+tid+"/scopes",{
    specificationId:sid,operationKeys:keys,fixtureId:"pt-security-v1",exclusions:[],
    maxEvaluations:14,ratePerMinute:14,maxConcurrency:1,deadlineMs:30000,validityMinutes:15
   },"e6-scope-"+randomUUID()),201);
   const scopeId=scope.id as string;
   ok(await call("POST","/v6/pt/scopes/"+scopeId+"/request-authorization",{}),201);
   const issue=await timed("first-signed-synthetic-permit-issue",
    "real /v6/pt/test-authority/scopes/:id/issue; exact HMAC persisted by test-only issuer")
    (()=>call("POST","/v6/pt/test-authority/scopes/"+scopeId+"/issue",{},undefined,true),i);
   ok(issue,201);
   const preview=await timed("governed-signed-permit-check-deterministic-plan",
    "real /v11/api-vapt/scopes/:id/preview validates current scope/permit and deterministic Phase09 plan")
    (()=>call("GET","/v11/api-vapt/scopes/"+scopeId+"/preview?policyId=SYNTHETIC_PT_COMPLETE_SUPPORTED&profile=SECURE_BASELINE"),i);
   assert.equal(ok(preview,200).authorizationReady,true);
   assert.equal((preview.json().plan as {plannedEvaluations:number}).plannedEvaluations,14);
   const body={mode:"GOVERNED_SYNTHETIC",scopeId,policyId:"SYNTHETIC_PT_COMPLETE_SUPPORTED",profile:"SECURE_BASELINE"};
   const admitted=await timed("first-autonomous-parent-child-postgres-admission",
    "real /v11/api-vapt/assessments creates parent+2 children with fresh idempotency and PostgreSQL queue")
    (()=>call("POST","/v11/api-vapt/assessments",body,"e6-parent-"+randomUUID()),i);
   const created=ok(admitted,201),id=created.id as string;
   assert(created.offlineAssessmentId&&created.ptAssessmentId);
   const replay=ok(await call("GET","/v11/api-vapt/assessments/"+id),200);
   assert.equal(replay.status,"QUEUED");assert.equal((replay.children as unknown[]).length,2);
   const offline=await timed("worker-claim-offline-child-real-execution",
    "processOneJob claims fenced private queue and persists offline evidence/worker attempt")
    (()=>processOneJob(),i);
   assert.equal(offline,true);
   const partial=ok(await call("GET","/v11/api-vapt/assessments/"+id),200);
   assert.equal(partial.status,"QUEUED");
   assert((partial.children as {engine_version:string;status:string}[]).some(v=>v.status==="COMPLETED"));
   const governed=await timed("worker-signed-governed-PT-stage-and-evaluation",
    "processOneJob executes Phase09 PT fixture, validates 14 signed evaluations, no external network")
    (()=>processOneJob(),i);
   assert.equal(governed,true);
   const compose=await timed("worker-immutable-parent-report-composition",
    "processOneJob dispatches processAutonomousVaptJob, persisted child evidence correlation and immutable report")
    (()=>processOneJob(),i);
   assert.equal(compose,true);
   const report=await timed("tenant-scoped-immutable-parent-report-retrieval",
    "authenticated GET /v11/api-vapt/assessments/:id/report real PG FORCED RLS")
    (()=>call("GET","/v11/api-vapt/assessments/"+id+"/report"),i);
   const document=ok(report,200);
   assert.equal(document.verifiedFixed,false);
   assert.equal(document.customerRuntimeVerified,false);
   assert.equal(document.fullAuthorizedVaptCompleted,true);
   assert.equal((document.pt as {executedEvaluations:number}).executedEvaluations,14);
   assert.equal((document.components as {status:string}[]).filter(x=>x.status==="COMPLETED").length,2);
   const findings=await timed("tenant-scoped-parent-finding-pagination",
    "authenticated GET /v11/api-vapt/assessments/:id/findings?limit=20 real PG")
    (()=>call("GET","/v11/api-vapt/assessments/"+id+"/findings?limit=20"),i);
   ok(findings,200);
   assert.equal((await call("GET","/v11/api-vapt/assessments/"+id+"/report",undefined,undefined,false,"local-test-token-beta")).statusCode,409);
   assert.equal((await withTenant(A,tx=>tx.query("SELECT count(*)::int AS n FROM api_vapt11_reports WHERE parent_assessment_id=$1",[id]))).rows[0].n,1);
   const src=await withTenant(A,tx=>tx.query("SELECT id FROM api_reports WHERE assessment_id=$1",[created.offlineAssessmentId]));
   assert.equal(src.rowCount,1,"source immutable offline report must exist before metering");
   reports.push(src.rows[0].id as string);
  }

  // Separate fresh pending parent operations measure durable recovery at a lost lease boundary.
  for(let i=0;i<samples;i++){
   const payload={mode:"OFFLINE_ONLY",targetId:tid,specificationId:sid};
   const id=ok(await call("POST","/v11/api-vapt/assessments",payload,"e6-recovery-"+randomUUID()),201).id as string;
   assert.equal(await processOneJob(),true);
   const old=await claimJob();assert.equal(old?.assessment_id,id);
   await withWorkerTenant(A,tx=>tx.query(
    "UPDATE api_queue.api_assessment_queue SET locked_until=clock_timestamp()-interval '1 second' WHERE assessment_id=$1",[id]));
   const replacement=await timed("fenced-private-queue-lease-reclaim",
    "claimJob takes expired PostgreSQL lease, increments generation, never reuses stale token")
    (()=>claimJob(),i);
   assert.equal(replacement?.assessment_id,id);assert.notEqual(old!.claim_token,replacement!.claim_token);
   await assert.rejects(()=>processAutonomousVaptJob(A,id,old!.claim_token),/VAPT11_PARENT_LEASE_LOST/);
   await timed("durable-parent-worker-recovery-after-stale-lease",
    "processAutonomousVaptJob reads actual committed offline child, rejects former worker and persists one report")
    (()=>processAutonomousVaptJob(A,id,replacement!.claim_token),i);
   assert.equal(ok(await call("GET","/v11/api-vapt/assessments/"+id+"/report"),200).verifiedFixed,false);
   assert.equal((await withTenant(A,tx=>tx.query(
    "SELECT count(*)::int AS n FROM api_vapt11_reports WHERE parent_assessment_id=$1",[id]))).rows[0].n,1);
  }

  for(let i=0;i<samples;i++){
   const id=ok(await call("POST","/v11/api-vapt/assessments",
    {mode:"OFFLINE_ONLY",targetId:tid,specificationId:sid},"e6-cancel-"+randomUUID()),201).id as string;
   const result=await timed("first-write-queued-parent-cancellation",
    "real POST /v11/api-vapt/assessments/:id/cancel commits terminal PostgreSQL parent/child states")
    (()=>call("POST","/v11/api-vapt/assessments/"+id+"/cancel",{}),i);
   assert.equal(ok(result,200).status,"CANCELLED");
   assert.equal((await call("GET","/v11/api-vapt/assessments/"+id+"/report")).statusCode,409);
   assert.equal((await withTenant(A,tx=>tx.query(
    "SELECT count(*)::int AS n FROM api_vapt11_reports WHERE parent_assessment_id=$1",[id]))).rows[0].n,0);
  }

  const key=randomBytes(48),now=Date.now();
  const raw=Buffer.from(JSON.stringify({schemaVersion:V13,eventId:randomUUID(),
   tenantId:A,issuer:"lumicsec-ci-synthetic-v13",audience:"api-family-v13-test",
   issuedAt:new Date(now).toISOString(),expiresAt:new Date(now+600000).toISOString(),
   entitlementId:randomUUID(),revision:1,feature,limit:samples,status:"ISSUED"}));
  assert.equal((await ingestSyntheticEntitlement(raw,
   createHmac("sha256",key).update(raw).digest("hex"),key)).replay,false);
  for(let i=0;i<samples;i++){
   const reservation=await timed("first-write-commercial-evidence-reservation",
    "reserveFeatureObservation creates committed unique non-billable offline source reservation under advisory lock")
    (()=>reserveFeatureObservation(A,reports[i]!,"e6-meter-"+randomUUID(),feature),i);
   assert.equal(reservation.replay,false);
   const settled=await timed("first-write-commercial-settlement",
    "settleFeatureObservation commits exact synthetic immutable usage ledger and disabled outbound outbox")
    (()=>settleFeatureObservation(A,reservation.id),i);
   assert.equal(settled.state,"SETTLED");assert.equal(settled.replay,false);
   const reconciled=await timed("first-write-commercial-pending-reconciliation",
    "reconcilePending detects actual latest ledger watermark and writes pending external authority evidence")
    (()=>reconcilePending(A,feature),i);
   assert.equal(reconciled.state,"PENDING_EXTERNAL_AUTHORITY");
  }
  const summary=await projection(A,feature);
  assert.equal(summary.consumed,samples);
  assert.equal(summary.billable,false);
  assert.equal(summary.hostAuthority,"HOST_AUTHORITY_NOT_CONFIGURED");
  assert.equal((await projection(B,feature)).consumed,0);
  const ledger=await withTenant(A,tx=>tx.query(
   "SELECT count(*)::int AS n FROM api_v13_usage_ledger WHERE feature=$1",[feature]));
  assert.equal(ledger.rows[0].n,samples);
  const outbox=await withTenant(A,tx=>tx.query(
   "SELECT count(*)::int AS n FROM api_v13_outbox WHERE delivery_state!='DISABLED'"));
  assert.equal(outbox.rows[0].n,0);
  emit();
 }finally{await app.close();}
});
