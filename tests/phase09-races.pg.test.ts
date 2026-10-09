import {test} from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {randomUUID} from "node:crypto";
import {Pool} from "pg";
import {makeApp} from "../packages/service/src/app.js";
import {migrate,withTenant,withWorkerTenant,claimJob,closeDatabase} from "../packages/database/src/index.js";
import {processOneJob} from "../packages/worker/src/index.js";
import {processPtOrchestrationJob} from "../packages/worker/src/pt-orchestrator.js";

const A="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",B="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const AUTH="local-test-token-alpha",SIGNER=process.env.PT_TEST_AUTHORITY_KEY??"";
const source=readFileSync(new URL("../fixtures/phase07-security.openapi.json",import.meta.url),"utf8");
type Response={statusCode:number;body:string;json:()=>Record<string,unknown>};
type Setup={targetId:string;scopeId:string;permitId:string;specId:string;ops:string[]};
test("Phase09 independently coordinated PostgreSQL transaction and orchestration security interleavings",async t=>{
 await migrate();
 const app=await makeApp();
 const admin=new Pool({connectionString:process.env.MIGRATION_DATABASE_URL,max:1});
 async function call(method:"GET"|"POST",path:string,data?:unknown,opts?:{key?:string;authority?:boolean;token?:string}):Promise<Response>{
  return app.inject({method,url:path,payload:data as object|undefined,headers:{
   authorization:"Bearer "+(opts?.token??AUTH),
   ...(opts?.key?{"idempotency-key":opts.key}:{}),
   ...(opts?.authority?{"x-pt-authority-key":SIGNER}:{})
  }});
 }
 const ok=(r:Response,status:number)=>assert.equal(r.statusCode,status,r.body);
 async function setup(budget=4,rate=4,concurrency=1):Promise<Setup>{
  const n=randomUUID().slice(0,8);
  const target=await call("POST","/v1/targets",{name:"P09 Race "+n,environment:"SYNTHETIC",
   baseUrl:"https://pt9-race-"+n+".fixture.invalid"});ok(target,201);
  const targetId=target.json().id as string;
  const imported=await call("POST","/v2/targets/"+targetId+"/specifications/imports",
   {filename:"phase07-security.openapi.json",content:source},{key:"pt9-race-import-"+randomUUID()});ok(imported,201);
  const specId=imported.json().specificationId as string;
  const list=await call("GET","/v2/specifications/"+specId+"/operations?limit=100");ok(list,200);
  const ops=(list.json() as unknown as {key:string;method:string;path:string}[])
   .filter(o=>o.method==="GET"&&["/pt/resources/bob","/pt/admin"].includes(o.path)).map(o=>o.key);
  assert.equal(ops.length,2);
  const created=await call("POST","/v6/pt/targets/"+targetId+"/scopes",{
   specificationId:specId,operationKeys:ops,fixtureId:"pt-security-v1",exclusions:[],
   maxEvaluations:budget,ratePerMinute:rate,maxConcurrency:concurrency,
   deadlineMs:30000,validityMinutes:15
  },{key:"pt9-race-scope-"+randomUUID()});ok(created,201);
  const scopeId=created.json().id as string;
  ok(await call("POST","/v6/pt/scopes/"+scopeId+"/request-authorization",{}),201);
  const issuer=await call("POST","/v6/pt/test-authority/scopes/"+scopeId+"/issue",{}, {authority:true});ok(issuer,201);
  return {targetId,scopeId,permitId:issuer.json().id as string,specId,ops};
 }
 async function admit(s:Setup,key="pt9-race-run-"+randomUUID(),profile="SECURE_BASELINE"){
  return call("POST","/v9/pt/scopes/"+s.scopeId+"/orchestrations",
   {policyId:"SYNTHETIC_PT_AUTHORIZATION_FOCUSED",profile},{key});
 }
 async function terminal(jid:string,status:"COMPLETED"|"FAILED"|"CANCELLED"){
  const r=await call("GET","/v9/pt/orchestrations/"+jid);ok(r,200);
  assert.equal(r.json().status,status,r.body);
 }
 try{
  await t.test("simultaneous identical idempotency key serialized to exactly one plan",async()=>{
   const s=await setup(),key="pt9-idem-race-"+randomUUID();
   const runs=await Promise.all(Array.from({length:8},()=>admit(s,key)));
   assert.equal(runs.filter(x=>x.statusCode===201).length,1,runs.map(x=>x.body).join("\n"));
   assert.equal(runs.filter(x=>x.statusCode===200).length,7);
   const ids=[...new Set(runs.map(x=>x.json().id as string))];
   assert.equal(ids.length,1);
   const stored=await withTenant(A,tx=>tx.query("SELECT count(*)::int AS n FROM api_pt9_plans WHERE assessment_id=$1",[ids[0]]));
   assert.equal(stored.rows[0].n,1);
   assert.equal(await processOneJob(),true);
   await terminal(ids[0]!,"COMPLETED");
  });
  await t.test("concurrent different idempotency keys honor permit active-concurrency ceiling",async()=>{
   const s=await setup(),runs=await Promise.all([admit(s),admit(s)]);
   assert.deepEqual(runs.map(r=>r.statusCode).sort(),[201,409],runs.map(r=>r.body).join("\n"));
   const jid=runs.find(r=>r.statusCode===201)!.json().id as string;
   assert.equal(await processOneJob(),true);
   await terminal(jid,"COMPLETED");
   const ledger=await withTenant(A,tx=>tx.query("SELECT consumed,reserved FROM api_pt_permits WHERE id=$1",[s.permitId]));
   assert.equal(ledger.rows[0].consumed,4);assert.equal(ledger.rows[0].reserved,0);
  });
  await t.test("idempotency conflict with a different trusted fixture profile never mutates existing plan",async()=>{
   const s=await setup(),key="pt9-conflict-"+randomUUID();
   const first=await admit(s,key);ok(first,201);
   const mismatch=await admit(s,key,"MISSING_AUTH_ENFORCEMENT");ok(mismatch,409);
   assert.equal(mismatch.json().error,"IDEMPOTENCY_CONFLICT");
   assert.equal((await withTenant(A,tx=>tx.query("SELECT count(*)::int AS n FROM api_pt9_plans WHERE assessment_id=$1",[first.json().id]))).rows[0].n,1);
   assert.equal(await processOneJob(),true);
  });
  await t.test("separate worker sessions compete conservatively for a shared permit budget",async()=>{
   const s=await setup(4,4,2);
   const [first,second]=await Promise.all([admit(s),admit(s)]);
   ok(first,201);ok(second,201);
   assert.equal(new Set([first.json().id,second.json().id]).size,2);
   const results=await Promise.all([processOneJob(),processOneJob()]);
   assert.deepEqual(results,[true,true]);
   const ledger=await withTenant(A,tx=>tx.query("SELECT consumed,reserved FROM api_pt_permits WHERE id=$1",[s.permitId]));
   assert.equal(ledger.rows[0].consumed,4);
   assert.equal(ledger.rows[0].reserved,0);
   const states=await withTenant(A,tx=>tx.query("SELECT id,status FROM api_assessments WHERE id=ANY($1::uuid[])",[[first.json().id,second.json().id]]));
   const completed=states.rows.filter(x=>x.status==="COMPLETED");
   const failed=states.rows.filter(x=>x.status==="FAILED");
   assert.ok(completed.length===0||completed.length===1,"competing partial consumption must not create two successful runs");
   assert.equal(completed.length+failed.length,2,"both workers must settle terminally without double-spend");
   for(const row of failed){
    const success=await withTenant(A,tx=>tx.query("SELECT 1 FROM api_pt9_reports WHERE assessment_id=$1",[row.id]));
    const terminal=await withTenant(A,tx=>tx.query("SELECT status FROM api_pt9_terminal WHERE assessment_id=$1",[row.id]));
    assert.equal(success.rowCount,0,"partially consumed competing run has no fabricated success report");
    assert.equal(terminal.rowCount,1,"failed competing run preserves diagnostic coverage");
   }
  });
  await t.test("rate governor does not admit more than four evaluations across concurrent jobs",async()=>{
   const s=await setup(8,4,2);
   const [a,b]=await Promise.all([admit(s),admit(s)]);
   ok(a,201);ok(b,201);
   assert.deepEqual(await Promise.all([processOneJob(),processOneJob()]),[true,true]);
   const p=await withTenant(A,tx=>tx.query("SELECT consumed,reserved,rate_used FROM api_pt_permits WHERE id=$1",[s.permitId]));
   assert.equal(p.rows[0].consumed,4);assert.equal(p.rows[0].reserved,0);assert.equal(p.rows[0].rate_used,4);
   const all=await withTenant(A,tx=>tx.query("SELECT state,count(*)::int AS n FROM api_pt_detection_evaluations WHERE assessment_id=ANY($1::uuid[]) GROUP BY state",[[a.json().id,b.json().id]]));
   assert.equal(all.rows.find(x=>x.state==="CONSUMED")?.n,4);
  });
  await t.test("private queue competing claims cannot share worker fencing token",async()=>{
   const s=await setup(),a=await admit(s);ok(a,201);
   const r=await Promise.all([claimJob(),claimJob()]);
   assert.equal(r.filter(Boolean).length,1);
   const lease=r.find(Boolean)!;
   assert.equal(lease.assessment_id,a.json().id);
   assert.match(lease.claim_token,/^[a-f0-9-]{36}$/);
   await withWorkerTenant(A,tx=>tx.query("UPDATE api_queue.api_assessment_queue SET locked_until=now()-interval '1 second' WHERE assessment_id=$1",[a.json().id]));
   assert.equal(await processOneJob(),true);
  });
  await t.test("stale leased claimant cannot advance or finalize after valid worker takeover",async()=>{
   const s=await setup(),r=await admit(s);ok(r,201);
   const jid=r.json().id as string;
   const old=await claimJob();assert.equal(old?.assessment_id,jid);
   await withWorkerTenant(A,tx=>tx.query("UPDATE api_assessments SET status='PROCESSING' WHERE id=$1 AND status='QUEUED'",[jid]));
   await processPtOrchestrationJob(A,jid,old!.claim_token,{afterCheckpoint:async step=>{
    if(step==="preflight")throw new Error("PT9_ISOLATED_PROCESS_EXIT");
   }});
   await withWorkerTenant(A,tx=>tx.query("UPDATE api_queue.api_assessment_queue SET locked_until=now()-interval '1 second' WHERE assessment_id=$1",[jid]));
   const next=await claimJob();assert.equal(next?.assessment_id,jid);
   assert.notEqual(next!.claim_token,old!.claim_token);
   await processPtOrchestrationJob(A,jid,old!.claim_token);
   await processPtOrchestrationJob(A,jid,next!.claim_token);
   await terminal(jid,"COMPLETED");
   const n=await withTenant(A,tx=>tx.query("SELECT code,count(*)::int AS n FROM api_pt9_decisions WHERE assessment_id=$1 AND code='STAGE_ADMITTED' AND stage_id='preflight' GROUP BY code",[jid]));
   assert.equal(n.rows[0].n,1);
  });
  await t.test("customer cannot forge stage completion or security verdict in orchestration body",async()=>{
   const s=await setup();
   const r=await call("POST","/v9/pt/scopes/"+s.scopeId+"/orchestrations",
    {policyId:"SYNTHETIC_PT_AUTHORIZATION_FOCUSED",profile:"SECURE_BASELINE",stageCompleted:true,findingConfirmed:true},
    {key:"pt9-fake-state-"+randomUUID()});
   ok(r,400);
   assert.equal((await withTenant(A,tx=>tx.query("SELECT count(*)::int AS n FROM api_pt9_plans p JOIN api_pt_jobs j ON j.assessment_id=p.assessment_id WHERE j.scope_id=$1",[s.scopeId]))).rows[0].n,0);
  });
  await t.test("out-of-order and PENDING-to-COMPLETED PostgreSQL stage transitions rejected",async()=>{
   const s=await setup(),r=await admit(s);ok(r,201);
   const jid=r.json().id as string;
   await assert.rejects(()=>withWorkerTenant(A,tx=>tx.query("UPDATE api_pt9_stages SET status='COMPLETED',started_at=now(),finished_at=now(),evidence_fingerprint=$2 WHERE assessment_id=$1 AND stage_id='authorization'",[jid,"a".repeat(64)])),/PT9_STAGE_TRANSITION_DENIED/);
   const row=await withTenant(A,tx=>tx.query("SELECT status FROM api_pt9_stages WHERE assessment_id=$1 AND stage_id='authorization'",[jid]));
   assert.equal(row.rows[0].status,"PENDING");
   assert.equal(await processOneJob(),true);
  });
  await t.test("unique stage identity enforced under concurrent duplicate checkpoint writes",async()=>{
   const s=await setup(),r=await admit(s);ok(r,201);
   const jid=r.json().id as string;
   const duplicates=await Promise.allSettled([withWorkerTenant(A,tx=>tx.query(
    "INSERT INTO api_pt9_stages(id,tenant_id,assessment_id,stage_id,stage_type,ordinal,dependencies,evaluation_keys,planned) VALUES($1,$2,$3,'preflight','PREFLIGHT',5,'[]'::jsonb,'[]'::jsonb,0)",
    [randomUUID(),A,jid])),
    withWorkerTenant(A,tx=>tx.query(
    "INSERT INTO api_pt9_stages(id,tenant_id,assessment_id,stage_id,stage_type,ordinal,dependencies,evaluation_keys,planned) VALUES($1,$2,$3,'preflight','PREFLIGHT',5,'[]'::jsonb,'[]'::jsonb,0)",
    [randomUUID(),A,jid]))]);
   assert.equal(duplicates.every(x=>x.status==="rejected"),true);
   assert.equal((await withTenant(A,tx=>tx.query("SELECT count(*)::int AS n FROM api_pt9_stages WHERE assessment_id=$1",[jid]))).rows[0].n,4);
   assert.equal(await processOneJob(),true);
  });
  await t.test("cross-tenant direct plan, stage and report mutations return zero affected rows",async()=>{
   const s=await setup(),r=await admit(s);ok(r,201);
   const jid=r.json().id as string;
   await withTenant(B,async tx=>{
    assert.equal((await tx.query("SELECT 1 FROM api_pt9_plans WHERE assessment_id=$1",[jid])).rowCount,0);
    assert.equal((await tx.query("SELECT 1 FROM api_pt9_stages WHERE assessment_id=$1",[jid])).rowCount,0);
   });
   const forbidden=await withWorkerTenant(B,tx=>tx.query(
    "UPDATE api_pt9_stages SET status='CANCELLED',reason='CROSS_TENANT',finished_at=now() WHERE assessment_id=$1",[jid]));
   assert.equal(forbidden.rowCount,0,"FORCE RLS must filter foreign-tenant stage mutations");
   assert.equal(await processOneJob(),true);
   assert.equal((await call("GET","/v9/pt/orchestrations/"+jid,undefined,{token:"local-test-token-beta"})).statusCode,404);
  });
  await t.test("immutable completed report and stage terminal state resist database mutation",async()=>{
   const s=await setup(),r=await admit(s);ok(r,201);
   const jid=r.json().id as string;
   assert.equal(await processOneJob(),true);
   const before=await withTenant(A,tx=>tx.query("SELECT projection FROM api_pt9_reports WHERE assessment_id=$1",[jid]));
   assert.equal(before.rowCount,1);
   await assert.rejects(()=>admin.query("UPDATE public.api_pt9_reports SET projection='{}'::jsonb WHERE assessment_id=$1",[jid]),/PHASE1_IMMUTABLE/);
   await assert.rejects(()=>admin.query("DELETE FROM public.api_pt9_reports WHERE assessment_id=$1",[jid]),/PHASE1_IMMUTABLE/);
   await assert.rejects(()=>withWorkerTenant(A,tx=>tx.query(
    "UPDATE api_pt9_stages SET status='RUNNING' WHERE assessment_id=$1 AND stage_id='finalization'",[jid])),/PT9_STAGE_TRANSITION_DENIED/);
   assert.deepEqual((await withTenant(A,tx=>tx.query("SELECT projection FROM api_pt9_reports WHERE assessment_id=$1",[jid]))).rows[0].projection,before.rows[0].projection);
  });
  await t.test("duplicate governed evaluation key cannot duplicate immutable budget receipt",async()=>{
   const s=await setup(),r=await admit(s);ok(r,201);
   const jid=r.json().id as string;
   assert.equal(await processOneJob(),true);
   const before=await withTenant(A,tx=>tx.query("SELECT count(*)::int AS n FROM api_pt_detection_evaluations WHERE assessment_id=$1",[jid]));
   assert.equal(before.rows[0].n,4);
   await assert.rejects(()=>withWorkerTenant(A,tx=>tx.query(
    "INSERT INTO api_pt_detection_evaluations(id,tenant_id,assessment_id,permit_id,evaluation_key,operation_key,method,path,actor,state,settled_at) SELECT $2,tenant_id,assessment_id,permit_id,evaluation_key,operation_key,method,path,actor,'UNCERTAIN',now() FROM api_pt_detection_evaluations WHERE assessment_id=$1 LIMIT 1",
    [jid,randomUUID()])),/duplicate key|unique constraint/);
   assert.equal((await withTenant(A,tx=>tx.query("SELECT count(*)::int AS n FROM api_pt_detection_evaluations WHERE assessment_id=$1",[jid]))).rows[0].n,4);
  });
  await t.test("cancellation after successful atomic publication cannot create contradictory terminal summary",async()=>{
   const s=await setup(),r=await admit(s);ok(r,201);
   const jid=r.json().id as string;
   assert.equal(await processOneJob(),true);
   const cancel=await call("POST","/v9/pt/orchestrations/"+jid+"/cancel",{});ok(cancel,409);
   assert.equal((await call("GET","/v9/pt/orchestrations/"+jid+"/terminal")).statusCode,409);
   assert.equal((await call("GET","/v9/pt/orchestrations/"+jid+"/report")).statusCode,200);
  });
  await t.test("revoked permit at durable stage boundary produces FAILED, not a forged success",async()=>{
   const s=await setup(),r=await admit(s);ok(r,201);
   const jid=r.json().id as string;
   const lease=await claimJob();assert.equal(lease?.assessment_id,jid);
   await withWorkerTenant(A,tx=>tx.query("UPDATE api_assessments SET status='PROCESSING' WHERE id=$1 AND status='QUEUED'",[jid]));
   await processPtOrchestrationJob(A,jid,lease!.claim_token,{afterCheckpoint:async stageId=>{
    if(stageId==="preflight"){
     const revoke=await call("POST","/v6/pt/test-authority/permits/"+s.permitId+"/revoke",{}, {authority:true});
     ok(revoke,200);
    }
   }});
   await terminal(jid,"FAILED");
   assert.equal((await call("GET","/v9/pt/orchestrations/"+jid+"/report")).statusCode,409);
   const p=await withTenant(A,tx=>tx.query("SELECT consumed,reserved FROM api_pt_permits WHERE id=$1",[s.permitId]));
   assert.equal(p.rows[0].consumed,0);assert.equal(p.rows[0].reserved,0);
  });

  await t.test("stop-row transactional barrier serializes orchestrator admission and denies new stage authority",async()=>{
   const s=await setup();
   await withWorkerTenant(A,tx=>tx.query("INSERT INTO api_pt_stop(tenant_id) VALUES($1) ON CONFLICT DO NOTHING",[A]));
   let entered=()=>{},release=()=>{};
   const locked=new Promise<void>(resolve=>entered=resolve);
   const gate=new Promise<void>(resolve=>release=resolve);
   const stopping=withWorkerTenant(A,async tx=>{
    await tx.query("SELECT enabled FROM api_pt_stop WHERE tenant_id=$1 FOR UPDATE",[A]);
    entered();
    await gate;
    await tx.query("UPDATE api_pt_stop SET enabled=true,generation=generation+1 WHERE tenant_id=$1",[A]);
   });
   await locked;
   const waiting=admit(s);
   release();
   await stopping;
   const denied=await waiting;ok(denied,409);
   assert.equal(denied.json().error,"EMERGENCY_STOP_ACTIVE");
   assert.equal((await withTenant(A,tx=>tx.query("SELECT count(*)::int AS n FROM api_pt9_plans o JOIN api_pt_jobs j ON j.assessment_id=o.assessment_id WHERE j.scope_id=$1",[s.scopeId]))).rows[0].n,0);
   ok(await call("POST","/v6/pt/test-authority/resume",{}, {authority:true}),200);
  });
  await t.test("expired job deadline prohibits first stage without spending signed permit budget",async()=>{
   const s=await setup(),r=await admit(s);ok(r,201);
   const jid=r.json().id as string;
   await withWorkerTenant(A,tx=>tx.query("UPDATE api_pt_jobs SET job_deadline=now()-interval '1 second' WHERE assessment_id=$1",[jid]));
   assert.equal(await processOneJob(),true);
   await terminal(jid,"FAILED");
   assert.equal((await withTenant(A,tx=>tx.query("SELECT count(*)::int AS n FROM api_pt_detection_evaluations WHERE assessment_id=$1",[jid]))).rows[0].n,0);
   assert.equal((await withTenant(A,tx=>tx.query("SELECT consumed,reserved FROM api_pt_permits WHERE id=$1",[s.permitId]))).rows[0].consumed,0);
   assert.equal((await call("GET","/v9/pt/orchestrations/"+jid+"/report")).statusCode,409);
  });
  await t.test("crash after reservation never replays RESERVED evaluation identity",async()=>{
   const s=await setup(),r=await admit(s);ok(r,201);
   const jid=r.json().id as string;
   const ownerKey=s.ops.find(x=>x.includes("/pt/resources/bob"));assert.ok(ownerKey);
   await withWorkerTenant(A,async tx=>{
    await tx.query("UPDATE api_pt_permits SET reserved=reserved+1 WHERE id=$1",[s.permitId]);
    await tx.query("INSERT INTO api_pt_detection_evaluations(id,tenant_id,assessment_id,permit_id,evaluation_key,operation_key,method,path,actor,state) VALUES($1,$2,$3,$4,'PT-BOLA-CROSS-USER:owner',$5,'GET','/pt/resources/bob','bob','RESERVED')",
     [randomUUID(),A,jid,s.permitId,ownerKey]);
   });
   assert.equal(await processOneJob(),true);
   await terminal(jid,"FAILED");
   const ledger=await withTenant(A,tx=>tx.query("SELECT state FROM api_pt_detection_evaluations WHERE assessment_id=$1",[jid]));
   assert.equal(ledger.rowCount,1);assert.equal(ledger.rows[0].state,"UNCERTAIN");
   const p=await withTenant(A,tx=>tx.query("SELECT consumed,reserved FROM api_pt_permits WHERE id=$1",[s.permitId]));
   assert.deepEqual([p.rows[0].consumed,p.rows[0].reserved],[1,0]);
   const diag=await call("GET","/v9/pt/orchestrations/"+jid+"/terminal");ok(diag,200);
   assert.equal((diag.json().accounting as Record<string,number>).uncertain,1);
  });
  await t.test("process death after persisted fixture response resumes from receipt without duplicate evaluation",async()=>{
   const s=await setup(),r=await admit(s);ok(r,201);
   const jid=r.json().id as string;
   const old=await claimJob();assert.equal(old?.assessment_id,jid);
   await withWorkerTenant(A,tx=>tx.query("UPDATE api_assessments SET status='PROCESSING' WHERE id=$1 AND status='QUEUED'",[jid]));
   await processPtOrchestrationJob(A,jid,old!.claim_token,{afterEvaluation:async count=>{
    if(count===1)throw new Error("PT9_ISOLATED_PROCESS_EXIT");
   }});
   const consumed=await withTenant(A,tx=>tx.query("SELECT state,count(*)::int AS n FROM api_pt_detection_evaluations WHERE assessment_id=$1 GROUP BY state",[jid]));
   assert.equal(consumed.rows.find(x=>x.state==="CONSUMED")?.n,1);
   await withWorkerTenant(A,tx=>tx.query("UPDATE api_queue.api_assessment_queue SET locked_until=now()-interval '1 second' WHERE assessment_id=$1",[jid]));
   const next=await claimJob();assert.equal(next?.assessment_id,jid);
   await processPtOrchestrationJob(A,jid,next!.claim_token);
   await terminal(jid,"COMPLETED");
   const result=await withTenant(A,tx=>tx.query("SELECT evaluation_key,count(*)::int AS n FROM api_pt_detection_evaluations WHERE assessment_id=$1 GROUP BY evaluation_key",[jid]));
   assert.equal(result.rowCount,4);assert.ok(result.rows.every(x=>x.n===1));
   const p=await withTenant(A,tx=>tx.query("SELECT consumed,reserved FROM api_pt_permits WHERE id=$1",[s.permitId]));
   assert.deepEqual([p.rows[0].consumed,p.rows[0].reserved],[4,0]);
  });
  await t.test("fixture response persistence failure remains UNCERTAIN without replay or fabricated result",async()=>{
   const s=await setup(),r=await admit(s);ok(r,201);
   const jid=r.json().id as string;
   try{
    await admin.query("CREATE OR REPLACE FUNCTION public.pt09_inject_evidence_fault() RETURNS trigger LANGUAGE plpgsql AS $pt9$ BEGIN IF NEW.state='CONSUMED' THEN RAISE EXCEPTION 'PT09_INJECT_EVIDENCE_FAULT'; END IF; RETURN NEW; END $pt9$");
    await admin.query("CREATE TRIGGER pt09_evidence_inject BEFORE UPDATE ON public.api_pt_detection_evaluations FOR EACH ROW EXECUTE FUNCTION public.pt09_inject_evidence_fault()");
    assert.equal(await processOneJob(),true);
   }finally{
    await admin.query("DROP TRIGGER IF EXISTS pt09_evidence_inject ON public.api_pt_detection_evaluations");
    await admin.query("DROP FUNCTION IF EXISTS public.pt09_inject_evidence_fault()");
   }
   await terminal(jid,"FAILED");
   const ledger=await withTenant(A,tx=>tx.query("SELECT state FROM api_pt_detection_evaluations WHERE assessment_id=$1",[jid]));
   assert.equal(ledger.rowCount,1);assert.equal(ledger.rows[0].state,"UNCERTAIN");
   const p=await withTenant(A,tx=>tx.query("SELECT consumed,reserved FROM api_pt_permits WHERE id=$1",[s.permitId]));
   assert.deepEqual([p.rows[0].consumed,p.rows[0].reserved],[1,0]);
   assert.equal((await call("GET","/v9/pt/orchestrations/"+jid+"/report")).statusCode,409);
  });
  await t.test("fault after rule receipt but before stage checkpoint retains consumed immutable evaluations",async()=>{
   const s=await setup(),r=await admit(s);ok(r,201);
   const jid=r.json().id as string;
   try{
    await admin.query("CREATE OR REPLACE FUNCTION public.pt09_inject_rule_fault() RETURNS trigger LANGUAGE plpgsql AS $pt9$ BEGIN RAISE EXCEPTION 'PT09_INJECT_RULE_FAULT'; END $pt9$");
    await admin.query("CREATE TRIGGER pt09_rule_inject BEFORE INSERT ON public.api_pt_detection_results FOR EACH ROW EXECUTE FUNCTION public.pt09_inject_rule_fault()");
    assert.equal(await processOneJob(),true);
   }finally{
    await admin.query("DROP TRIGGER IF EXISTS pt09_rule_inject ON public.api_pt_detection_results");
    await admin.query("DROP FUNCTION IF EXISTS public.pt09_inject_rule_fault()");
   }
   await terminal(jid,"FAILED");
   const p=await withTenant(A,tx=>tx.query("SELECT consumed,reserved FROM api_pt_permits WHERE id=$1",[s.permitId]));
   assert.deepEqual([p.rows[0].consumed,p.rows[0].reserved],[4,0]);
   assert.equal((await withTenant(A,tx=>tx.query("SELECT count(*)::int AS n FROM api_pt_detection_results WHERE assessment_id=$1",[jid]))).rows[0].n,0);
   assert.equal((await call("GET","/v9/pt/orchestrations/"+jid+"/report")).statusCode,409);
  });
  await t.test("crash during atomic final report insertion rolls back any apparent success",async()=>{
   const s=await setup(),r=await admit(s);ok(r,201);
   const jid=r.json().id as string;
   try{
    await admin.query("CREATE OR REPLACE FUNCTION public.pt09_inject_publication_fault() RETURNS trigger LANGUAGE plpgsql AS $pt9$ BEGIN RAISE EXCEPTION 'PT09_INJECT_REPORT_FAULT'; END $pt9$");
    await admin.query("CREATE TRIGGER pt09_publication_inject BEFORE INSERT ON public.api_pt9_reports FOR EACH ROW EXECUTE FUNCTION public.pt09_inject_publication_fault()");
    assert.equal(await processOneJob(),true);
   }finally{
    await admin.query("DROP TRIGGER IF EXISTS pt09_publication_inject ON public.api_pt9_reports");
    await admin.query("DROP FUNCTION IF EXISTS public.pt09_inject_publication_fault()");
   }
   await terminal(jid,"FAILED");
   const state=await withTenant(A,tx=>tx.query("SELECT status FROM api_pt9_stages WHERE assessment_id=$1 AND stage_id='finalization'",[jid]));
   assert.equal(state.rows[0].status,"FAILED");
   assert.equal((await withTenant(A,tx=>tx.query("SELECT 1 FROM api_pt9_reports WHERE assessment_id=$1",[jid]))).rowCount,0);
   assert.equal((await withTenant(A,tx=>tx.query("SELECT 1 FROM api_pt9_terminal WHERE assessment_id=$1",[jid]))).rowCount,1);
  });
  await t.test("customer cancellation after reconciliation but before atomic publication cannot publish success",async()=>{
   const s=await setup(),r=await admit(s);ok(r,201);
   const jid=r.json().id as string;
   const lease=await claimJob();assert.equal(lease?.assessment_id,jid);
   await withWorkerTenant(A,tx=>tx.query("UPDATE api_assessments SET status='PROCESSING' WHERE id=$1 AND status='QUEUED'",[jid]));
   await processPtOrchestrationJob(A,jid,lease!.claim_token,{afterCheckpoint:async stageId=>{
    if(stageId==="reconciliation"){
     const cancel=await call("POST","/v9/pt/orchestrations/"+jid+"/cancel",{});ok(cancel,200);
    }
   }});
   await terminal(jid,"CANCELLED");
   assert.equal((await withTenant(A,tx=>tx.query("SELECT 1 FROM api_pt9_reports WHERE assessment_id=$1",[jid]))).rowCount,0);
   const diagnostic=await call("GET","/v9/pt/orchestrations/"+jid+"/terminal");ok(diagnostic,200);
   const accounting=diagnostic.json().accounting as {consumed:number;notRun:number};
   assert.equal(accounting.consumed,4);assert.equal(accounting.notRun,0);
  });
  await t.test("foreign-tenant plan mutation is denied without altering plan fingerprint",async()=>{
   const s=await setup(),r=await admit(s);ok(r,201);
   const jid=r.json().id as string;
   const before=await withTenant(A,tx=>tx.query("SELECT fingerprint FROM api_pt9_plans WHERE assessment_id=$1",[jid]));
   const foreign=await withTenant(B,tx=>tx.query("SELECT 1 FROM api_pt9_plans WHERE assessment_id=$1",[jid]));
   assert.equal(foreign.rowCount,0);
   await assert.rejects(()=>withWorkerTenant(B,tx=>tx.query("UPDATE api_pt9_plans SET fingerprint=$2 WHERE assessment_id=$1",[jid,"b".repeat(64)])),
    /permission denied/);
   await assert.rejects(()=>admin.query("UPDATE public.api_pt9_plans SET fingerprint=$2 WHERE assessment_id=$1",[jid,"b".repeat(64)]),
    /PHASE1_IMMUTABLE/);
   assert.equal((await withTenant(A,tx=>tx.query("SELECT fingerprint FROM api_pt9_plans WHERE assessment_id=$1",[jid]))).rows[0].fingerprint,
    before.rows[0].fingerprint);
   assert.equal(await processOneJob(),true);
  });
  await t.test("concurrent final publication versus cancellation commits exactly one terminal authority",async()=>{
   const s=await setup(),r=await admit(s);ok(r,201);
   const jid=r.json().id as string;
   const lease=await claimJob();assert.equal(lease?.assessment_id,jid);
   await withWorkerTenant(A,tx=>tx.query("UPDATE api_assessments SET status='PROCESSING' WHERE id=$1 AND status='QUEUED'",[jid]));
   let reached=()=>{},release=()=>{};
   const atBoundary=new Promise<void>(resolve=>reached=resolve);
   const gate=new Promise<void>(resolve=>release=resolve);
   const execution=processPtOrchestrationJob(A,jid,lease!.claim_token,{afterCheckpoint:async stageId=>{
    if(stageId==="reconciliation"){reached();await gate;}
   }});
   await atBoundary;
   const competingCancel=call("POST","/v9/pt/orchestrations/"+jid+"/cancel",{});
   release();
   await execution;
   const cancellation=await competingCancel;
   assert.ok([200,409].includes(cancellation.statusCode),cancellation.body);
   const status=await call("GET","/v9/pt/orchestrations/"+jid);ok(status,200);
   const reports=await withTenant(A,tx=>tx.query("SELECT 1 FROM api_pt9_reports WHERE assessment_id=$1",[jid]));
   const terminals=await withTenant(A,tx=>tx.query("SELECT 1 FROM api_pt9_terminal WHERE assessment_id=$1",[jid]));
   assert.equal(reports.rowCount+terminals.rowCount,1,"atomic publication versus cancel must choose one result");
   if(status.json().status==="COMPLETED"){
    assert.equal(reports.rowCount,1);assert.equal(terminals.rowCount,0);
    assert.equal(cancellation.statusCode,409);
   }else{
    assert.equal(status.json().status,"CANCELLED");
    assert.equal(reports.rowCount,0);assert.equal(terminals.rowCount,1);
    assert.equal(cancellation.statusCode,200);
   }
  });
 }finally{
  await app.close();await admin.end();await closeDatabase();
 }
});
