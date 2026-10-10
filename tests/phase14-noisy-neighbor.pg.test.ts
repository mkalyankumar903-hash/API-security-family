/** Sustained two-tenant PostgreSQL+Fastify+worker offline load, no customer traffic. */
import {test,after} from "node:test";
import assert from "node:assert/strict";
import {randomUUID} from "node:crypto";
import {performance} from "node:perf_hooks";
import {makeApp} from "../packages/service/src/app.js";
import {migrate,withTenant,withWorkerTenant,workerPool,pool,closeDatabase} from "../packages/database/src/index.js";
import {processOneJob} from "../packages/worker/src/index.js";
const A="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
 B="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const SPEC=JSON.stringify({openapi:"3.1.0",info:{title:"Noisy tenant isolation",version:"1.0.0"},
 paths:{"/safe":{get:{responses:{"200":{description:"OFFLINE ONLY"}}}}}});
after(async()=>{await closeDatabase();});
function quantiles(values:number[]){
 assert(values.length>0);const a=[...values].sort((x,y)=>x-y);
 return {samples:a.length,medianMs:Number(a[Math.floor((a.length-1)/2)]!.toFixed(3)),
  p95Ms:Number(a[Math.ceil(.95*a.length)-1]!.toFixed(3)),maxMs:Number(a.at(-1)!.toFixed(3))};
}
test("Phase14 PostgreSQL sustained 68:10 imbalanced tenant admission, fairness and starvation-free completion",async()=>{
 await migrate();
 const app=await makeApp(),submissions=new Map<string,string[]>([[A,[]],[B,[]]]);
 const token=(tenant:string)=>tenant===A?"local-test-token-alpha":"local-test-token-beta";
 const call=(tenant:string,url:string,body:object,key?:string)=>app.inject({method:"POST",url,
  payload:body,headers:{authorization:"Bearer "+token(tenant),...(key?{"idempotency-key":key}:{})}});
 const fixtureId=new Map<string,{target:string;spec:string}>();
 const baselineHeap=process.memoryUsage().heapUsed;
 let capacityDenied=0,checkedMax=0,loops=0;
 try{
  for(const tenant of [A,B]){
   const t=await call(tenant,"/v1/targets",{name:"Noisy "+randomUUID().slice(0,8),
    baseUrl:"https://noisy-"+randomUUID()+".fixture.invalid",environment:"SYNTHETIC"});
   assert.equal(t.statusCode,201,t.body);
   const target=t.json().id as string;
   const p=await call(tenant,"/v1/targets/"+target+"/specifications",{filename:"offline.json",content:SPEC});
   assert.equal(p.statusCode,201,p.body);
   fixtureId.set(tenant,{target,spec:p.json().id as string});
  }
  const begun=performance.now(),submitTimes:number[]=[];
  for(const [tenant,n] of [[A,68],[B,10]] as const){
   const fixture=fixtureId.get(tenant)!;
   for(let i=0;i<n;i++){
    const start=performance.now();
    const a=await call(tenant,"/v1/targets/"+fixture.target+"/assessments",
     {specificationId:fixture.spec,mode:"SPEC_ONLY"},"noisy-"+randomUUID());
    submitTimes.push(performance.now()-start);
    if(a.statusCode===201)submissions.get(tenant)!.push(a.json().id as string);
    else {
     assert.equal(tenant,A);
     assert.equal(a.statusCode,429,a.body);
     assert.match(a.body,/QUEUE_TENANT_CAPACITY_EXCEEDED/);
     capacityDenied++;
    }
   }
  }
  const aIds=submissions.get(A)!,bIds=submissions.get(B)!;
  assert.equal(aIds.length,64);
  assert.equal(bIds.length,10);
  assert.equal(capacityDenied,4);
  const all=[...aIds,...bIds];
  const done=new Set<string>(),maxActive={A:0,B:0};
  const startedAt=performance.now();
  await Promise.all(Array.from({length:3},async()=>{
   while(done.size<all.length&&performance.now()-startedAt<60000){
    loops++;
    const work=await processOneJob();
    if(!work)await new Promise(resolve=>setTimeout(resolve,30));
    const rows=await withTenant(A,tx=>tx.query(
      "SELECT id,status FROM api_assessments WHERE id=ANY($1::uuid[]) AND status IN ('COMPLETED','FAILED','CANCELLED')",[aIds]));
    const rowB=await withTenant(B,tx=>tx.query(
      "SELECT id,status FROM api_assessments WHERE id=ANY($1::uuid[]) AND status IN ('COMPLETED','FAILED','CANCELLED')",[bIds]));
    for(const entry of [...rows.rows,...rowB.rows])done.add(String(entry.id));
    const activeA=await withWorkerTenant(A,tx=>tx.query(
      "SELECT count(*)::int AS n FROM api_queue.api_assessment_queue WHERE tenant_id=$1 AND locked_until>clock_timestamp()",[A]));
    const activeB=await withWorkerTenant(B,tx=>tx.query(
      "SELECT count(*)::int AS n FROM api_queue.api_assessment_queue WHERE tenant_id=$1 AND locked_until>clock_timestamp()",[B]));
    maxActive.A=Math.max(maxActive.A,activeA.rows[0].n);
    maxActive.B=Math.max(maxActive.B,activeB.rows[0].n);
   }
  }));
  assert.equal(done.size,74,"both eligible tenants must complete all bounded work, no starvation");
  assert(maxActive.A<=2&&maxActive.B<=2,"max two fenced claims per tenant");
  const rows=await withTenant(A,tx=>tx.query(
    "SELECT id,status FROM api_assessments WHERE id=ANY($1::uuid[]) ORDER BY id",[aIds]));
  const other=await withTenant(B,tx=>tx.query(
    "SELECT id,status FROM api_assessments WHERE id=ANY($1::uuid[]) ORDER BY id",[bIds]));
  assert(rows.rows.every(x=>x.status==="COMPLETED"));
  assert(other.rows.every(x=>x.status==="COMPLETED"));
  for(const tenant of [A,B]){
   const ids=submissions.get(tenant)!;
   const history=await withTenant(tenant,tx=>tx.query(
    `SELECT a.id,a.created_at,b.started_at,b.state,
       extract(epoch FROM b.started_at-a.created_at)*1000 AS wait_ms
      FROM api_assessments a JOIN api_worker_attempts b ON b.assessment_id=a.id
      WHERE a.id=ANY($1::uuid[]) ORDER BY b.started_at,b.id`,[ids]));
   assert.equal(history.rowCount,ids.length,"one terminal worker attempt per job");
   assert(history.rows.every(x=>x.state==="COMPLETED"));
   const waits=history.rows.map(x=>Math.max(0,Number(x.wait_ms)));
   const results=quantiles(waits);
   assert(results.maxMs<60000,"bounded fixture lab cycle; not an SLO");
   console.log("PHASE14_TENANT_QUEUE_WAIT "+JSON.stringify({
    tenantClass:tenant===A?"heavy":"light",submitted:tenant===A?68:10,
    admitted:ids.length,rejected:tenant===A?4:0,finished:ids.length,failed:0,
    ...results,workerConcurrency:3,observedMaxTenantActive:tenant===A?maxActive.A:maxActive.B}));
  }
  const ordered=await withWorkerTenant(A,tx=>tx.query(
    "SELECT tenant_id,assessment_id FROM api_worker_attempts WHERE assessment_id=ANY($1::uuid[]) ORDER BY started_at,id",[all]));
  assert.equal(ordered.rowCount,74);
  const firstLight=ordered.rows.findIndex(x=>x.tenant_id===B);
  const lastLight=Math.max(...ordered.rows.map((x,i)=>x.tenant_id===B?i:-1));
  assert(firstLight>=0&&firstLight<=10,"light tenant must be claimed early despite 64 heavy queued");
  assert(lastLight<73,"light tenant never waits for full heavy backlog drain");
  const cross=await withTenant(B,tx=>tx.query("SELECT count(*)::int AS n FROM api_reports WHERE assessment_id=ANY($1::uuid[])",[aIds]));
  assert.equal(cross.rows[0].n,0,"no cross-tenant report readback");
  const counts=await withTenant(A,tx=>tx.query("SELECT count(*)::int AS n FROM api_reports WHERE assessment_id=ANY($1::uuid[])",[aIds]));
  assert.equal(counts.rows[0].n,64);
  const ledger=await withTenant(A,tx=>tx.query("SELECT count(*)::int AS n FROM api_v13_usage_ledger WHERE source_report_id=ANY($1::uuid[])",[aIds]));
  assert.equal(ledger.rows[0].n,0,"no synthetic offline job causes commercial settlement");
  const grants=await pool.query("SELECT has_table_privilege('api_family_queue','public.api_v13_usage_ledger','SELECT') AS usage_read");
  assert.equal(grants.rows[0].usage_read,false);
  const after=await call(B,"/v1/targets/"+fixtureId.get(B)!.target+"/assessments",
   {specificationId:fixtureId.get(B)!.spec,mode:"SPEC_ONLY"},"after-load-"+randomUUID());
  assert.equal(after.statusCode,201,after.body);
  const id=after.json().id as string;
  let recovered=false;
  for(let i=0;i<10;i++){
   await processOneJob();
   const current=await withTenant(B,tx=>tx.query("SELECT status FROM api_assessments WHERE id=$1",[id]));
   if(current.rows[0].status==="COMPLETED"){recovered=true;break;}
  }
  assert(recovered,"fresh work after heavy load must still complete");
  console.log("PHASE14_NOISY_NEIGHBOR_PASS "+JSON.stringify({
   submitted:78,admitted:74,rejected:4,completed:74,failed:0,
   completionElapsedMs:Number((performance.now()-startedAt).toFixed(2)),
   admissions:quantiles(submitTimes),workerConcurrency:3,firstLightClaimRank:firstLight+1,
   lastLightClaimRank:lastLight+1,tailRecovery:true,heapDeltaBytes:process.memoryUsage().heapUsed-baselineHeap,
   customerNetworkRequests:0,environment:"GitHub hosted PostgreSQL16 loopback only",
   timingBudget:"no production SLO"}));
 }finally{await app.close();}
});
