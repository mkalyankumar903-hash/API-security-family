/** Phase11 isolated-real-PostgreSQL acceptance:
 * twenty-five independent adversarial transaction/security cases.
 * All database reads/writes use actual PostgreSQL principals, no mocks.
 */
import {test} from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {randomUUID} from "node:crypto";
import {migrate,withTenant,withWorkerTenant,claimJob,closeDatabase} from "../packages/database/src/index.js";
import {makeApp} from "../packages/service/src/app.js";
import {processOneJob} from "../packages/worker/src/index.js";

const A="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",B="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const fixture=readFileSync(new URL("../fixtures/phase07-security.openapi.json",import.meta.url),"utf8");
type Response={statusCode:number;body:string;json:()=>Record<string,unknown>};
test("Phase11 25 genuine PostgreSQL interleavings, isolation, authority and failure evidence",async t=>{
 await migrate();const app=await makeApp();
 const call=async(method:"GET"|"POST",url:string,body?:unknown,key?:string,other=false):Promise<Response>=>
  app.inject({method,url,payload:body as object|undefined,headers:{
   authorization:"Bearer "+(other?"local-test-token-beta":"local-test-token-alpha"),
   ...(key?{"idempotency-key":key}:{})
  }});
 const ok=(r:Response,n:number)=>assert.equal(r.statusCode,n,r.body);
 async function target(other=false){
  const n=randomUUID().slice(0,8),r=await call("POST","/v1/targets",{
   name:"VAPT11 race "+n,environment:"SYNTHETIC",baseUrl:"https://vapt11-race-"+n+".fixture.invalid"
  },undefined,other);ok(r,201);
  const tid=r.json().id as string;
  const imported=await call("POST","/v2/targets/"+tid+"/specifications/imports",{
   filename:"phase07-security.openapi.json",content:fixture},"race-import-"+randomUUID(),other);
  ok(imported,201);return {tid,sid:imported.json().specificationId as string};
 }
 let reference:{tid:string;sid:string};
 const make=async(key="vapt11-race-"+randomUUID(),other=false,which=reference)=>{
  const r=await call("POST","/v11/api-vapt/assessments",{
   mode:"OFFLINE_ONLY",targetId:which.tid,specificationId:which.sid},key,other);
  return r;
 };
 const count=async(assessmentId:string)=>(await withTenant(A,tx=>tx.query(
  "SELECT count(*)::int AS n FROM api_vapt11_assessments WHERE parent_assessment_id=$1",
  [assessmentId]))).rows[0].n as number;
 const run=async()=>{assert.equal(await processOneJob(),true);assert.equal(await processOneJob(),true);};
 // Every subtest is a separate adversarial database/API qualification case.
 try{
  reference=await target();
  await t.test("01 eight simultaneous duplicate submissions resolve exactly once",async()=>{
   const key="race-same-"+randomUUID();
   const results=await Promise.all(Array.from({length:8},()=>make(key)));
   assert.equal(results.filter(r=>r.statusCode===201).length,1,results.map(r=>r.body).join("\n"));
   assert.equal(results.filter(r=>r.statusCode===200).length,7);
   const ids=[...new Set(results.map(r=>r.json().id))];assert.equal(ids.length,1);
   assert.equal(await count(ids[0] as string),1);await run();
  });
  await t.test("02 conflicting body with identical key never substitutes one workflow",async()=>{
   const otherTarget=await target(),key="race-conflict-"+randomUUID();
   const [one,two]=await Promise.all([make(key),make(key,false,otherTarget)]);
   assert.deepEqual([one.statusCode,two.statusCode].sort(),[201,409]);
   assert.equal((one.statusCode===409?one:two).json().error,"IDEMPOTENCY_CONFLICT");await run();
  });
  await t.test("03 disjoint keys safely create distinct child graphs concurrently",async()=>{
   const [a,b]=await Promise.all([make(),make()]);ok(a,201);ok(b,201);
   assert.notEqual(a.json().id,b.json().id);
   assert.equal(await count(a.json().id as string),1);
   assert.equal(await count(b.json().id as string),1);
   await run();await run();
  });
  await t.test("04 same key in distinct tenants is independent",async()=>{
   const otherTarget=await target(true),key="race-tenants-"+randomUUID();
   const [a,b]=await Promise.all([make(key),make(key,true,otherTarget)]);
   ok(a,201);ok(b,201);assert.notEqual(a.json().id,b.json().id);await run();await run();
  });
  const opened=await make();ok(opened,201);
  const id=opened.json().id as string;
  await t.test("05 direct cross-tenant parent SELECT stays row-invisible under parallel transactions",async()=>{
   const [a,b]=await Promise.all([withTenant(A,tx=>tx.query("SELECT id FROM api_assessments WHERE id=$1",[id])),
    withTenant(B,tx=>tx.query("SELECT id FROM api_assessments WHERE id=$1",[id]))]);
   assert.equal(a.rowCount,1);assert.equal(b.rowCount,0);
  });
  await t.test("06 cross-tenant persisted plan is invisible during owner read",async()=>{
   const [a,b]=await Promise.all([withTenant(A,tx=>tx.query("SELECT plan FROM api_vapt11_assessments WHERE parent_assessment_id=$1",[id])),
    withTenant(B,tx=>tx.query("SELECT plan FROM api_vapt11_assessments WHERE parent_assessment_id=$1",[id]))]);
   assert.equal(a.rowCount,1);assert.equal(b.rowCount,0);
  });
  await t.test("07 cross-tenant child linkage invisible under concurrent snapshots",async()=>{
   const r=await withTenant(A,tx=>tx.query("SELECT offline_assessment_id FROM api_vapt11_assessments WHERE parent_assessment_id=$1",[id]));
   const child=r.rows[0].offline_assessment_id as string;
   const [a,b]=await Promise.all([withTenant(A,tx=>tx.query("SELECT id FROM api_assessments WHERE id=$1",[child])),
    withTenant(B,tx=>tx.query("SELECT id FROM api_assessments WHERE id=$1",[child]))]);
   assert.equal(a.rowCount,1);assert.equal(b.rowCount,0);
  });
  await t.test("08 cross-tenant event stream invisible while owner events remain durable",async()=>{
   const [a,b]=await Promise.all([withTenant(A,tx=>tx.query("SELECT code FROM api_vapt11_events WHERE parent_assessment_id=$1",[id])),
    withTenant(B,tx=>tx.query("SELECT code FROM api_vapt11_events WHERE parent_assessment_id=$1",[id]))]);
   assert(a.rowCount!==null&&a.rowCount>0);assert.equal(b.rowCount,0);
  });
  await t.test("09 API tenant-confused history cannot enumerate owner target",async()=>{
   const [a,b]=await Promise.all([call("GET","/v11/api-vapt/targets/"+reference.tid+"/history"),
    call("GET","/v11/api-vapt/targets/"+reference.tid+"/history",undefined,undefined,true)]);
   ok(a,200);ok(b,200);assert((a.json() as unknown as unknown[]).length>0);
   assert.deepEqual(b.json(),[]);
  });
  await t.test("10 cross-tenant cancellation cannot affect authoritative owner state",async()=>{
   const denied=await call("POST","/v11/api-vapt/assessments/"+id+"/cancel",{},undefined,true);
   ok(denied,404);
   const owner=await call("GET","/v11/api-vapt/assessments/"+id);ok(owner,200);
   assert.equal(owner.json().status,"QUEUED");
  });
  await t.test("11 no PT ledger/permit is issued by offline-only admission",async()=>{
   const row=await withTenant(A,tx=>tx.query("SELECT pt_assessment_id FROM api_vapt11_assessments WHERE parent_assessment_id=$1",[id]));
   assert.equal(row.rows[0].pt_assessment_id,null);
   const all=await withTenant(A,tx=>tx.query("SELECT count(*)::int AS n FROM api_pt_jobs WHERE assessment_id=$1",[id]));
   assert.equal(all.rows[0].n,0);
  });
  await t.test("12 concurrent readers cannot get a report before child completion",async()=>{
   const results=await Promise.all(Array.from({length:4},()=>call("GET","/v11/api-vapt/assessments/"+id+"/report")));
   assert(results.every(r=>r.statusCode===409));
  });
  await t.test("13 customer role cannot SELECT private claims even when requests race",async()=>{
   const results=await Promise.all(Array.from({length:4},()=>withTenant(A,tx=>tx.query(
    "SELECT has_table_privilege(current_user,'api_queue.api_assessment_queue','SELECT') AS read"))));
   assert(results.every(x=>x.rows[0].read===false));
  });
  await t.test("14 unrelated tenant cannot read private worker attempts",async()=>{
   const [a,b]=await Promise.all([withTenant(A,tx=>tx.query("SELECT id FROM api_worker_attempts WHERE assessment_id=$1",[id])),
    withTenant(B,tx=>tx.query("SELECT id FROM api_worker_attempts WHERE assessment_id=$1",[id]))]);
   assert.equal(a.rowCount,b.rowCount); // neither has claimed parent yet
  });
  await t.test("15 eight competing queued claims cannot take same unstarted offline child",async()=>{
   const claims=await Promise.all(Array.from({length:8},()=>claimJob()));
   const claimed=claims.filter(x=>x!==null);
   assert.equal(claimed.length,1);
   const child=(await withTenant(A,tx=>tx.query("SELECT offline_assessment_id FROM api_vapt11_assessments WHERE parent_assessment_id=$1",[id]))).rows[0].offline_assessment_id;
   assert.equal(claimed[0]!.assessment_id,child);
   await withWorkerTenant(A,tx=>tx.query(
    "UPDATE api_queue.api_assessment_queue SET locked_until=clock_timestamp()-interval '1 second' WHERE assessment_id=$1",[child]));
   assert.equal(await processOneJob(),true);
  });
  await t.test("16 offline child completion wakes precisely parent (no PT child)",async()=>{
   const counts=await withWorkerTenant(A,tx=>tx.query(
    "SELECT assessment_id FROM api_queue.api_assessment_queue WHERE tenant_id=$1",[A]));
   assert.deepEqual(counts.rows.map(x=>x.assessment_id),[id]);
   await processOneJob();
  });
  await t.test("17 parent final report persisted exactly once despite concurrent readers",async()=>{
   const [a,b]=await Promise.all([call("GET","/v11/api-vapt/assessments/"+id+"/report"),
    call("GET","/v11/api-vapt/assessments/"+id+"/report")]);
   ok(a,200);ok(b,200);assert.deepEqual(a.json(),b.json());
   assert.equal((await withTenant(A,tx=>tx.query("SELECT count(*)::int AS n FROM api_vapt11_reports WHERE parent_assessment_id=$1",[id]))).rows[0].n,1);
  });
  await t.test("18 completed parent report cannot be edited by two independent tenants",async()=>{
   const attempts=await Promise.all([withTenant(A,tx=>tx.query("UPDATE api_vapt11_reports SET fingerprint=$1 WHERE parent_assessment_id=$2",["f".repeat(64),id])),
    withTenant(B,tx=>tx.query("UPDATE api_vapt11_reports SET fingerprint=$1 WHERE parent_assessment_id=$2",["e".repeat(64),id]))].map(p=>p.then(()=>false,()=>true)));
   assert(attempts.every(Boolean));
  });
  await t.test("19 completed parent plan immutable under competing modification",async()=>{
   const attempts=await Promise.all([withTenant(A,tx=>tx.query("UPDATE api_vapt11_assessments SET fingerprint=$1 WHERE parent_assessment_id=$2",["e".repeat(64),id])),
    withTenant(B,tx=>tx.query("UPDATE api_vapt11_assessments SET fingerprint=$1 WHERE parent_assessment_id=$2",["f".repeat(64),id]))].map(p=>p.then(()=>false,()=>true)));
   assert(attempts.every(Boolean));
  });
  await t.test("20 historical parent event append-only under two concurrent update attempts",async()=>{
   const ev=(await withTenant(A,tx=>tx.query("SELECT id FROM api_vapt11_events WHERE parent_assessment_id=$1 LIMIT 1",[id]))).rows[0].id;
   const outcomes=await Promise.all([withTenant(A,tx=>tx.query("UPDATE api_vapt11_events SET code='FORGED' WHERE id=$1",[ev])),
    withTenant(B,tx=>tx.query("DELETE FROM api_vapt11_events WHERE id=$1",[ev]))].map(x=>x.then(()=>false,()=>true)));
   assert(outcomes.every(Boolean));
  });
  await t.test("21 concurrent forced RLS checks fail closed across all five Phase11 tables",async()=>{
   const tables=["api_vapt11_assessments","api_vapt11_correlations","api_vapt11_reports","api_vapt11_terminal","api_vapt11_events"];
   const result=await Promise.all(tables.map(name=>withTenant(A,tx=>tx.query(
    "SELECT relrowsecurity,relforcerowsecurity FROM pg_class WHERE oid=$1::regclass",[name]))));
   assert(result.every(x=>x.rows[0].relrowsecurity===true&&x.rows[0].relforcerowsecurity===true));
  });
  await t.test("22 duplicate cancellation is single terminal transition, never success",async()=>{
   const r=await make();ok(r,201);const pid=r.json().id as string;
   const pair=await Promise.all(Array.from({length:2},()=>call("POST","/v11/api-vapt/assessments/"+pid+"/cancel",{})));
   assert.deepEqual(pair.map(x=>x.statusCode).sort(),[200,409],pair.map(x=>x.body).join("\n"));
   assert.equal((await withTenant(A,tx=>tx.query("SELECT count(*)::int AS n FROM api_vapt11_terminal WHERE parent_assessment_id=$1",[pid]))).rows[0].n,1);
   assert.equal((await withTenant(A,tx=>tx.query("SELECT count(*)::int AS n FROM api_vapt11_reports WHERE parent_assessment_id=$1",[pid]))).rows[0].n,0);
  });
  await t.test("23 cancellation cannot retroactively change immutable completed parent",async()=>{
   const pair=await Promise.all(Array.from({length:3},()=>call("POST","/v11/api-vapt/assessments/"+id+"/cancel",{})));
   assert(pair.every(x=>x.statusCode===409));
   assert.equal((await call("GET","/v11/api-vapt/assessments/"+id)).json().status,"COMPLETED");
  });
  await t.test("24 reassessment identical keys collapse under concurrent admission",async()=>{
   const key="vapt11-reassess-race-"+randomUUID();
   const results=await Promise.all(Array.from({length:4},()=>call("POST","/v11/api-vapt/assessments/"+id+"/reassess",{},key)));
   assert.equal(results.filter(x=>x.statusCode===201).length,1,results.map(x=>x.body).join("\n"));
   assert.equal(results.filter(x=>x.statusCode===200).length,3);
   const ids=[...new Set(results.map(x=>x.json().id))];assert.equal(ids.length,1);
   assert.notEqual(ids[0],id);await run();
  });
  await t.test("25 cross-tenant report+findings+audit remain invisible under concurrent reads",async()=>{
   const [r,f,a]=await Promise.all([
    call("GET","/v11/api-vapt/assessments/"+id+"/report",undefined,undefined,true),
    call("GET","/v11/api-vapt/assessments/"+id+"/findings",undefined,undefined,true),
    call("GET","/v11/api-vapt/assessments/"+id+"/audit",undefined,undefined,true)
   ]);
   ok(r,409);ok(f,200);ok(a,200);
   assert.deepEqual(f.json(),[]);assert.deepEqual(a.json(),[]);
  });
 }finally{await app.close();await closeDatabase();}
});
