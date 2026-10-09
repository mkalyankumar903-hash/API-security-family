import {test} from "node:test";
import assert from "node:assert/strict";
import {randomUUID} from "node:crypto";
import {readFileSync} from "node:fs";
import {Pool} from "pg";
import {makeApp} from "../packages/service/src/app.js";
import {pool,workerPool,withTenant,withWorkerTenant,migrate} from "../packages/database/src/index.js";
import {processOneJob} from "../packages/worker/src/index.js";
const TENANT="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const OTHER="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const KEY=process.env.PT_TEST_AUTHORITY_KEY??"";
const fixture=readFileSync(new URL("../fixtures/phase2-openapi30-v1.json",import.meta.url),"utf8");
test("Phase06 true competing PostgreSQL transactions: permit admission, budget, global stop, stale lease, fault recovery",async t=>{
 await migrate();
 const app=await makeApp();
 const call=async(method:"GET"|"POST",url:string,payload?:unknown,key?:string,authority=false,tenant="alpha")=>
  app.inject({method,url,headers:{authorization:"Bearer local-test-token-"+tenant,...(key?{"idempotency-key":key}:{}),...(authority?{"x-pt-authority-key":KEY}:{})},payload:payload as object|undefined});
 async function create(budget=3,concurrency=2,rate=10){
  const n=randomUUID().slice(0,8);
  const target=await call("POST","/v1/targets",{name:"PT-Race-"+n,baseUrl:"https://pt-race-"+n+".fixture.invalid",environment:"SYNTHETIC"});
  assert.equal(target.statusCode,201,target.body);
  const tid=target.json().id as string;
  const uploaded=await call("POST","/v2/targets/"+tid+"/specifications/imports",{filename:"phase2-openapi30-v1.json",content:fixture},"pt6-race-import-"+randomUUID());
  assert.equal(uploaded.statusCode,201,uploaded.body);
  const sid=uploaded.json().specificationId as string;
  const ops=await call("GET","/v2/specifications/"+sid+"/operations?limit=100");
  const keys=(ops.json() as {key:string;method:string;path:string}[]).filter(x=>x.method==="GET"&&x.path==="/status").map(x=>x.key);
  assert.equal(keys.length,1);
  const scope=await call("POST","/v6/pt/targets/"+tid+"/scopes",{
   specificationId:sid,operationKeys:keys,exclusions:[],maxEvaluations:budget,maxConcurrency:concurrency,
   ratePerMinute:rate,deadlineMs:15000,validityMinutes:10,fixtureId:"billing-safe-v1"
  },"pt6-race-scope-"+randomUUID());
  assert.equal(scope.statusCode,201,scope.body);
  const scopeId=scope.json().id as string;
  assert.equal((await call("POST","/v6/pt/scopes/"+scopeId+"/request-authorization")).statusCode,201);
  return {targetId:tid,specificationId:sid,scopeId,keys};
 }
 async function issue(sid:string){
  const response=await call("POST","/v6/pt/test-authority/scopes/"+sid+"/issue",{},undefined,true);
  assert.equal(response.statusCode===200||response.statusCode===201,true,response.body);
  return response.json().id as string;
 }
 async function queue(sid:string,keys:string[],idempotency="pt6-race-job-"+randomUUID()){
  return call("POST","/v6/pt/scopes/"+sid+"/jobs",{operationKeys:keys},idempotency);
 }
 const admin=new Pool({connectionString:process.env.MIGRATION_DATABASE_URL,max:1});
 try{
  await t.test("simultaneous distinct clients issue only one signed permit per scope",async()=>{
   const s=await create();
   const results=await Promise.all(Array.from({length:8},()=>call("POST","/v6/pt/test-authority/scopes/"+s.scopeId+"/issue",{},undefined,true)));
   assert.equal(results.filter(x=>x.statusCode===201).length,1,results.map(x=>x.body).join("\n"));
   assert.equal(results.filter(x=>x.statusCode===200).length,7);
   assert.equal(new Set(results.map(x=>x.json().id)).size,1);
   assert.equal((await withTenant(TENANT,tx=>tx.query("SELECT count(*)::int AS n FROM api_pt_permits WHERE scope_id=$1",[s.scopeId]))).rows[0].n,1);
  });
  await t.test("eight concurrent calls with identical idempotency key create exactly one queued job",async()=>{
   const s=await create();await issue(s.scopeId);
   const key="pt6-same-"+randomUUID();
   const result=await Promise.all(Array.from({length:8},()=>queue(s.scopeId,s.keys,key)));
   assert.equal(result.filter(x=>x.statusCode===201).length,1,result.map(x=>x.body).join("\n"));
   assert.equal(result.filter(x=>x.statusCode===200).length,7);
   const ids=new Set(result.map(x=>x.json().id));
   assert.equal(ids.size,1);
   assert.equal((await withTenant(TENANT,tx=>tx.query("SELECT count(*)::int AS n FROM api_pt_jobs WHERE assessment_id=$1",[[...ids][0]]))).rows[0].n,1);
   assert.equal(await processOneJob(),true);
  });
  await t.test("two worker processes contend for a single evaluation budget: no overspending",async()=>{
   const s=await create(1,2,2);const pid=await issue(s.scopeId);
   const r=await Promise.all([queue(s.scopeId,s.keys),queue(s.scopeId,s.keys)]);
   assert.ok(r.every(x=>x.statusCode===201),r.map(x=>x.body).join("\n"));
   const [a,b]=r.map(x=>x.json().id as string);
   const workers=await Promise.all([processOneJob(),processOneJob()]);
   assert.deepEqual(workers,[true,true]);
   const receipts=await withTenant(TENANT,tx=>tx.query("SELECT decision,count(*)::int AS n FROM api_pt_receipts WHERE assessment_id=ANY($1::uuid[]) GROUP BY decision",[[a,b]]));
   const allowed=receipts.rows.filter(x=>x.decision==="ALLOWED").reduce((n,x)=>n+x.n,0);
   assert.equal(allowed,1);
   const p=await withTenant(TENANT,tx=>tx.query("SELECT consumed,reserved FROM api_pt_permits WHERE id=$1",[pid]));
   assert.deepEqual([p.rows[0].consumed,p.rows[0].reserved],[1,0]);
   const reports=await withTenant(TENANT,tx=>tx.query("SELECT status,count(*)::int AS n FROM api_assessments WHERE id=ANY($1::uuid[]) GROUP BY status",[[a,b]]));
   assert.equal(reports.rows.reduce((x,y)=>x+y.n,0),2);
  });
  await t.test("test authority STOP transaction vs concurrently blocked job admission must deny after commit",async()=>{
   const s=await create();await issue(s.scopeId);
   let release=()=>{};let notify=()=>{};
   const holding=new Promise<void>(resolve=>notify=resolve);
   const barrier=new Promise<void>(resolve=>release=resolve);
   const holdingTx=withTenant(TENANT,async tx=>{
    await tx.query("SELECT enabled FROM api_pt_stop WHERE tenant_id=$1 FOR UPDATE",[TENANT]);
    notify();await barrier;
    await tx.query("UPDATE api_pt_stop SET enabled=true,generation=generation+1 WHERE tenant_id=$1",[TENANT]);
   });
   await holding;
   const requested=queue(s.scopeId,s.keys);
   await new Promise(resolve=>setTimeout(resolve,25));
   release();await holdingTx;
   const response=await requested;
   assert.equal(response.statusCode,409,response.body);
   assert.equal(response.json().error,"EMERGENCY_STOP_ACTIVE");
   assert.equal((await withTenant(TENANT,tx=>tx.query("SELECT count(*)::int AS n FROM api_pt_jobs WHERE scope_id=$1",[s.scopeId]))).rows[0].n,0);
   const resume=await call("POST","/v6/pt/test-authority/resume",{},undefined,true);
   assert.equal(resume.statusCode,200,resume.body);
  });
  await t.test("stale lease with durable pre-evaluation RESERVED ledger is recovered without replay",async()=>{
   const s=await create(1,1,5),pid=await issue(s.scopeId);
   const job=await queue(s.scopeId,s.keys);assert.equal(job.statusCode,201,job.body);
   const jid=job.json().id as string,lease=await (await import("../packages/database/src/index.js")).claimJob();
   assert.equal(lease?.assessment_id,jid);
   await withWorkerTenant(TENANT,async tx=>{
    await tx.query("UPDATE api_pt_permits SET reserved=reserved+1 WHERE id=$1",[pid]);
    await tx.query("INSERT INTO api_pt_ledger(id,tenant_id,assessment_id,permit_id,operation_key,state) VALUES($1,$2,$3,$4,$5,'RESERVED')",[randomUUID(),TENANT,jid,pid,s.keys[0]]);
    await tx.query("UPDATE api_queue.api_assessment_queue SET locked_until=now()-interval '1 minute' WHERE assessment_id=$1",[jid]);
   });
   assert.equal(await processOneJob(),true);
   const state=await withTenant(TENANT,tx=>tx.query("SELECT p.consumed,p.reserved,l.state FROM api_pt_permits p JOIN api_pt_ledger l ON l.permit_id=p.id WHERE p.id=$1 AND l.assessment_id=$2",[pid,jid]));
   assert.deepEqual([state.rows[0].consumed,state.rows[0].reserved,state.rows[0].state],[1,0,"UNCERTAIN"]);
   const receipt=await withTenant(TENANT,tx=>tx.query("SELECT decision,code FROM api_pt_receipts WHERE assessment_id=$1",[jid]));
   assert.equal(receipt.rows[0].decision,"SKIPPED");
   assert.equal(receipt.rows[0].code,"RESERVATION_RECOVERED_NO_REPLAY");
   assert.equal((await call("GET","/v6/pt/jobs/"+jid)).json().status,"FAILED");
  });
  await t.test("fault injected into immutable receipt publication rolls back execution and conservatively settles reservation",async()=>{
   const s=await create(1,1,5),pid=await issue(s.scopeId);
   const job=await queue(s.scopeId,s.keys);assert.equal(job.statusCode,201);
   const jid=job.json().id as string;
   try{
    await admin.query("CREATE OR REPLACE FUNCTION public.pt06_injected_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'PT06_INJECTED_FAULT'; END $$");
    await admin.query("CREATE TRIGGER pt06_test_receipt_fault BEFORE INSERT ON public.api_pt_receipts FOR EACH ROW EXECUTE FUNCTION public.pt06_injected_fault()");
    assert.equal(await processOneJob(),true);
   }finally{
    await admin.query("DROP TRIGGER IF EXISTS pt06_test_receipt_fault ON public.api_pt_receipts");
    await admin.query("DROP FUNCTION IF EXISTS public.pt06_injected_fault()");
   }
   const q=await withTenant(TENANT,tx=>tx.query("SELECT a.status,a.error_code,p.consumed,p.reserved,l.state FROM api_assessments a JOIN api_pt_jobs j ON j.assessment_id=a.id JOIN api_pt_permits p ON p.id=j.permit_id JOIN api_pt_ledger l ON l.assessment_id=a.id WHERE a.id=$1",[jid]));
   assert.equal(q.rows[0].status,"FAILED");
   assert.equal(q.rows[0].error_code,"PT_WORKER_FAILURE");
   assert.equal(q.rows[0].consumed,1);
   assert.equal(q.rows[0].reserved,0);
   assert.equal(q.rows[0].state,"UNCERTAIN");
   const count=await withTenant(TENANT,tx=>tx.query("SELECT count(*)::int AS n FROM api_pt_reports WHERE assessment_id=$1",[jid]));
   assert.equal(count.rows[0].n,0,"never publish success after fault");
   const p=await withTenant(TENANT,tx=>tx.query("SELECT consumed,reserved FROM api_pt_permits WHERE id=$1",[pid]));
   assert.deepEqual([p.rows[0].consumed,p.rows[0].reserved],[1,0]);
  });
  await t.test("cross-tenant concurrent reads on permit, audit and budget ledger remain empty",async()=>{
   const tables=["api_pt_permits","api_pt_receipts","api_pt_ledger","api_pt_events","api_pt_reports"];
   const results=await Promise.all(tables.map(table=>withTenant(OTHER,tx=>tx.query("SELECT count(*)::int AS n FROM "+table))));
   assert.ok(results.every(x=>x.rows[0].n===0));
  });
 }finally{
  await admin.query("DROP TRIGGER IF EXISTS pt06_test_receipt_fault ON public.api_pt_receipts");
  await admin.query("DROP FUNCTION IF EXISTS public.pt06_injected_fault()");
  await admin.end();await app.close();await pool.end();await workerPool.end();
 }
});
