import {test} from "node:test";
import assert from "node:assert/strict";
import {randomUUID} from "node:crypto";
import {readFileSync} from "node:fs";
import {makeApp} from "../packages/service/src/app.js";
import {migrate,pool,workerPool,withTenant,withWorkerTenant,claimJob} from "../packages/database/src/index.js";
import {processOneJob,drainQueue} from "../packages/worker/src/index.js";
const TENANT="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const OTHER="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const token="local-test-token-alpha";
const admin=process.env.PT_TEST_AUTHORITY_KEY??"";
const fixture=(x:string)=>readFileSync(new URL("../fixtures/"+x,import.meta.url),"utf8");
type Response={statusCode:number;body:string;json:()=>Record<string,unknown>};
type Api=(method:"GET"|"POST",url:string,payload?:unknown,opts?:{token?:string;key?:string;authority?:boolean})=>Promise<Response>;
type Setup={targetId:string;specId:string;keys:string[]};
test("Phase06 real PostgreSQL: full isolated PT workflow and transaction contention",async t=>{
 await migrate();const app=await makeApp();
 const call:Api=async(method,url,payload,opts={})=>app.inject({method,url,
  headers:{authorization:"Bearer "+(opts.token??token),...(opts.key?{"idempotency-key":opts.key}:{}),
   ...(opts.authority?{"x-pt-authority-key":admin}:{})},
  payload:payload as object|undefined});
 async function seed(name="phase2-openapi30-v1.json"):Promise<Setup>{
  const suffix=randomUUID().slice(0,10);
  const target=await call("POST","/v1/targets",{name:"PT6-"+suffix,baseUrl:"https://pt6-"+suffix+".fixture.invalid",environment:"SYNTHETIC"});
  assert.equal(target.statusCode,201,target.body);
  const tid=target.json().id as string;
  const imported=await call("POST","/v2/targets/"+tid+"/specifications/imports",{filename:name,content:fixture(name)},
   {key:"pt6-import-"+randomUUID()});
  assert.equal(imported.statusCode,201,imported.body);
  const sid=imported.json().specificationId as string;
  const operations=await call("GET","/v2/specifications/"+sid+"/operations?limit=100");
  assert.equal(operations.statusCode,200);
  const keys=(operations.json() as unknown as {key:string;method:string;path:string}[])
   .filter(x=>x.method==="GET"&&["/bills","/status"].includes(x.path)).map(x=>x.key);
  assert.ok(keys.length>0,"trusted fixture GET operation should exist");
  return {targetId:tid,specId:sid,keys};
 }
 async function propose(s:Setup,options?:{budget?:number;rate?:number;concurrency?:number;keys?:string[];exclusions?:string[]}){
  return call("POST","/v6/pt/targets/"+s.targetId+"/scopes",{
   specificationId:s.specId,operationKeys:options?.keys??s.keys,exclusions:options?.exclusions??[],
   maxEvaluations:options?.budget??5,maxConcurrency:options?.concurrency??1,
   ratePerMinute:options?.rate??10,deadlineMs:15000,validityMinutes:10,fixtureId:"billing-safe-v1"
  },{key:"pt6-scope-"+randomUUID()});
 }
 async function requestAndIssue(sid:string){
  const requested=await call("POST","/v6/pt/scopes/"+sid+"/request-authorization");
  assert.equal(requested.statusCode,201,requested.body);
  const denied=await call("POST","/v6/pt/test-authority/scopes/"+sid+"/issue");
  assert.equal(denied.statusCode,403);
  const issued=await call("POST","/v6/pt/test-authority/scopes/"+sid+"/issue",{}, {authority:true});
  assert.equal(issued.statusCode,201,issued.body);
  return issued.json().id as string;
 }
 async function queue(sid:string,keys:string[],idem="pt6-job-"+randomUUID()){
  return call("POST","/v6/pt/scopes/"+sid+"/jobs",{operationKeys:keys},{key:idem});
 }
 async function job(id:string){const r=await call("GET","/v6/pt/jobs/"+id);assert.equal(r.statusCode,200,r.body);return r.json();}
 async function receipts(id:string){const r=await call("GET","/v6/pt/jobs/"+id+"/receipts");assert.equal(r.statusCode,200);return r.json() as unknown as {decision:string;code:string;http_status:number}[];}
 try{
  await t.test("fresh version 009, FORCE RLS, least privilege and preserved migration lineage",async()=>{
   assert.equal((await pool.query("SELECT count(*)::int AS n FROM api_schema_migrations WHERE version IN('001','002','003','004','005','006','007','008','009','010')")).rows[0].n,10);
   const r=await pool.query("SELECT c.relname,c.relrowsecurity,c.relforcerowsecurity FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname LIKE 'api_pt_%' AND c.relkind='r'");
   assert.equal(r.rowCount,14,"Phase06 ten preserved tables plus four additive Phase07 tables");
   assert.ok(r.rows.every(x=>x.relrowsecurity&&x.relforcerowsecurity));
   await assert.rejects(()=>pool.query("SELECT * FROM api_queue.api_assessment_queue"),/permission denied/);
   const state=await withTenant(TENANT,tx=>tx.query("SELECT count(*)::int AS n FROM api_pt_permits"));
   assert.ok(state.rows[0].n>=0);
  });
  const s=await seed();
  await t.test("scope validation: tenant, synthetic ownership and forbidden methods",async()=>{
   const foreign=await call("POST","/v6/pt/targets/"+s.targetId+"/scopes",{
    specificationId:s.specId,operationKeys:s.keys,maxEvaluations:2,maxConcurrency:1,ratePerMinute:1,
    deadlineMs:5000,validityMinutes:1,fixtureId:"billing-safe-v1"
   },{token:"local-test-token-beta",key:"pt6-foreign-"+randomUUID()});
   assert.equal(foreign.statusCode,404);
   const invalid=await propose(s,{keys:["UNKNOWN /path"]});
   assert.equal(invalid.statusCode,409,invalid.body);
   const unsafe=await seed("phase2-openapi30-v2.json");
   const ops=await call("GET","/v2/specifications/"+unsafe.specId+"/operations?limit=100");
   const post=(ops.json() as unknown as {key:string;method:string}[]).find(x=>x.method==="POST");
   assert.ok(post);
   assert.equal((await propose(unsafe,{keys:[post!.key]})).statusCode,409);
  });
  const sc=await propose(s);
  assert.equal(sc.statusCode,201,sc.body);
  const scopeId=sc.json().id as string;
  await t.test("permit absent: persisted denial and zero fixture evaluation",async()=>{
   const result=await queue(scopeId,s.keys);
   assert.equal(result.statusCode,409);
   assert.equal(result.json().error,"AUTHORIZATION_MISSING");
   const denials=await call("GET","/v6/pt/scopes/"+scopeId+"/denials");
   assert.equal((denials.json() as unknown as {code:string}[])[0]!.code,"AUTHORIZATION_MISSING");
   assert.equal((await withTenant(TENANT,tx=>tx.query("SELECT count(*)::int AS n FROM api_pt_receipts"))).rows[0].n,0);
  });
  const permit=await requestAndIssue(scopeId);
  await t.test("test-only issuer, signed permit metadata and browser spoof rejection",async()=>{
   const p=await call("GET","/v6/pt/permits/"+permit);
   assert.equal(p.statusCode,200);assert.equal(p.json().state,"SYNTHETIC_TEST_ONLY_VALID");
   assert.equal(p.body.includes("signed_token"),false);
   assert.equal((await call("GET","/v6/pt/permits/"+permit,undefined,{token:"local-test-token-beta"})).statusCode,404);
   const record=await withTenant(TENANT,tx=>tx.query("SELECT claims,token_hash FROM api_pt_permits WHERE id=$1",[permit]));
   assert.match(record.rows[0].token_hash,/^[0-9a-f]{64}$/);
   assert.equal(record.rows[0].claims.permitId,permit);
   assert.equal((await pool.query("SELECT count(*)::int AS n FROM information_schema.columns WHERE table_name='api_pt_permits' AND column_name='signed_token'")).rows[0].n,0);
   await assert.rejects(()=>withTenant(TENANT,tx=>tx.query("UPDATE api_pt_permits SET token_hash=$2 WHERE id=$1",[permit,"0".repeat(64)])),/permission denied|PT_PERMIT_IMMUTABLE/);
  });
  await t.test("authorized worker + actual fixture injection + immutable report + idempotency",async()=>{
   const idem="pt6-replay-"+randomUUID(),start=await queue(scopeId,s.keys,idem);
   assert.equal(start.statusCode,201,start.body);
   const runId=start.json().id as string;
   const same=await queue(scopeId,s.keys,idem);
   assert.equal(same.statusCode,200);
   assert.equal(same.json().id,runId);
   assert.equal(await processOneJob(),true);
   const detail=await job(runId);
   assert.equal(detail.status,"COMPLETED");
   const evidence=await receipts(runId);
   assert.equal(evidence.length,s.keys.length);
   assert.ok(evidence.every(x=>x.decision==="ALLOWED"&&x.http_status===200));
   const report=await call("GET","/v6/pt/jobs/"+runId+"/report");
   assert.equal(report.statusCode,200,report.body);
   assert.equal(report.json().customerNetworkRequests,0);
   assert.equal(report.json().verifiedFixed,false);
   const sameReport=await call("GET","/v6/pt/jobs/"+runId+"/report");
   assert.equal(sameReport.body,report.body);
   assert.equal((await call("GET","/v6/pt/jobs/"+runId+"/receipts",undefined,{token:"local-test-token-beta"})).statusCode,404);
   await assert.rejects(()=>withTenant(TENANT,tx=>tx.query("UPDATE api_pt_receipts SET code='HACK' WHERE assessment_id=$1",[runId])),/PHASE1_IMMUTABLE|permission denied/);
   await assert.rejects(()=>withTenant(TENANT,tx=>tx.query("UPDATE api_pt_reports SET projection='{}'::jsonb WHERE assessment_id=$1",[runId])),/PHASE1_IMMUTABLE|permission denied/);
  });
  await t.test("permit cannot exceed atomic budget or retroactively enlarge scope",async()=>{
   const narrow=await propose(await seed(),{budget:1,keys:s.keys.slice(0,1)});
   // Cross-target operation key value is allowed only if present on the new spec;
   // scope/target identities are always bound independently by the permit.
   assert.equal(narrow.statusCode,201,narrow.body);
   const id=narrow.json().id as string;
   await requestAndIssue(id);
   const scope=await call("GET","/v6/pt/scopes/"+id);
   const keys=(scope.json().scope as {operation_keys:string[]}).operation_keys;
   const ok=await queue(id,keys);
   assert.equal(ok.statusCode,201,ok.body);
   assert.equal(await processOneJob(),true);
   assert.equal((await job(ok.json().id as string)).status,"COMPLETED");
   const exhausted=await queue(id,keys);
   assert.equal(exhausted.statusCode,409);
   assert.equal(exhausted.json().error,"PERMIT_BUDGET_EXHAUSTED");
   const count=await withTenant(TENANT,tx=>tx.query("SELECT consumed,reserved FROM api_pt_permits WHERE scope_id=$1",[id]));
   assert.equal(count.rows[0].consumed,1);assert.equal(count.rows[0].reserved,0);
  });
  await t.test("concurrent job admissions obey atomic cap and persist deterministic denial",async()=>{
   const fresh=await seed(),sc=await propose(fresh,{concurrency:1});
   assert.equal(sc.statusCode,201);
   const sid=sc.json().id as string;await requestAndIssue(sid);
   const results=await Promise.all(Array.from({length:5},()=>queue(sid,fresh.keys)));
   assert.equal(results.filter(x=>x.statusCode===201).length,1,results.map(x=>x.body).join("\n"));
   assert.equal(results.filter(x=>x.statusCode===409&&x.json().error==="CONCURRENCY_LIMIT").length,4);
   assert.equal(await drainQueue(),1);
  });
  await t.test("rate competition denies subsequent allowed operation without overspending",async()=>{
   const fresh=await seed(),sc=await propose(fresh,{budget:3,rate:1});
   const sid=sc.json().id as string;await requestAndIssue(sid);
   const start=await queue(sid,fresh.keys);assert.equal(start.statusCode,201,start.body);
   assert.equal(await processOneJob(),true);
   const r=await job(start.json().id as string);
   assert.equal(r.status,"FAILED");
   const receiptsNow=await receipts(start.json().id as string);
   assert.equal(receiptsNow.filter(x=>x.decision==="ALLOWED").length,1);
   assert.equal(receiptsNow.filter(x=>x.code==="RATE_LIMIT").length,fresh.keys.length-1);
  });
  await t.test("explicit exclusions prevent job admission",async()=>{
   const fresh=await seed(),sc=await propose(fresh,{exclusions:["/status"]});
   const sid=sc.json().id as string;await requestAndIssue(sid);
   const denied=await queue(sid,fresh.keys);
   assert.equal(denied.statusCode,409);
   assert.equal(denied.json().error,"PATH_EXCLUDED");
  });
  await t.test("revocation before admission blocks further job attempts",async()=>{
   const fresh=await seed(),sc=await propose(fresh);
   const sid=sc.json().id as string,pid=await requestAndIssue(sid);
   assert.equal((await call("POST","/v6/pt/test-authority/permits/"+pid+"/revoke",{}, {authority:true})).statusCode,200);
   assert.equal((await queue(sid,fresh.keys)).json().error,"PERMIT_REVOKED");
   assert.equal((await call("POST","/v6/pt/test-authority/permits/"+pid+"/revoke",{}, {authority:false})).statusCode,403);
  });
  await t.test("permit revoked after queueing denies fixture evaluations before execution",async()=>{
   const fresh=await seed(),sc=await propose(fresh),sid=sc.json().id as string,pid=await requestAndIssue(sid);
   const pending=await queue(sid,fresh.keys);assert.equal(pending.statusCode,201);
   assert.equal((await call("POST","/v6/pt/test-authority/permits/"+pid+"/revoke",{}, {authority:true})).statusCode,200);
   assert.equal(await processOneJob(),true);
   assert.equal((await job(pending.json().id as string)).status,"FAILED");
   assert.ok((await receipts(pending.json().id as string)).every(r=>r.decision!=="ALLOWED"));
  });
  await t.test("cancel queued job, no phantom report or fixture receipt",async()=>{
   const fresh=await seed(),sc=await propose(fresh),sid=sc.json().id as string;
   await requestAndIssue(sid);
   const pending=await queue(sid,fresh.keys);assert.equal(pending.statusCode,201);
   const jid=pending.json().id as string;
   assert.equal((await call("POST","/v6/pt/jobs/"+jid+"/cancel")).statusCode,200);
   assert.equal((await job(jid)).status,"CANCELLED");
   assert.equal((await receipts(jid)).length,0);
   assert.equal((await call("GET","/v6/pt/jobs/"+jid+"/report")).statusCode,409);
  });
  await t.test("emergency stop cancels queued jobs, revokes permits and cannot be browser-restarted",async()=>{
   const fresh=await seed(),sc=await propose(fresh),sid=sc.json().id as string;
   await requestAndIssue(sid);
   const pending=await queue(sid,fresh.keys);assert.equal(pending.statusCode,201);
   const stop=await call("POST","/v6/pt/test-authority/stop",{}, {authority:true});
   assert.equal(stop.statusCode,200,stop.body);
   assert.equal((await job(pending.json().id as string)).status,"CANCELLED");
   assert.equal((await queue(sid,fresh.keys)).json().error,"EMERGENCY_STOP_ACTIVE");
   assert.equal((await call("POST","/v6/pt/test-authority/resume")).statusCode,403);
   const resume=await call("POST","/v6/pt/test-authority/resume",{}, {authority:true});
   assert.equal(resume.statusCode,200,resume.body);
   assert.equal((await queue(sid,fresh.keys)).json().error,"PERMIT_REVOKED");
   const history=await withTenant(TENANT,tx=>tx.query("SELECT count(*)::int AS n FROM api_pt_events WHERE action='PT_EMERGENCY_STOP'"));
   assert.ok(history.rows[0].n>=1);
  });
  await t.test("stale lease reclaim by second worker executes fixture once",async()=>{
   const fresh=await seed(),sc=await propose(fresh),sid=sc.json().id as string;
   await requestAndIssue(sid);
   const queued=await queue(sid,[fresh.keys[0]!]);assert.equal(queued.statusCode,201);
   const jid=queued.json().id as string,lease=await claimJob();
   assert.equal(lease?.assessment_id,jid);
   await withWorkerTenant(TENANT,tx=>tx.query("UPDATE api_queue.api_assessment_queue SET locked_until=now()-interval '1 minute' WHERE assessment_id=$1",[jid]));
   assert.equal(await processOneJob(),true);
   assert.equal((await job(jid)).status,"COMPLETED");
   assert.equal((await receipts(jid)).length,1);
   assert.equal(await processOneJob(),false);
  });
  await t.test("competing private workers claim a job exactly once",async()=>{
   const fresh=await seed(),sc=await propose(fresh),sid=sc.json().id as string;
   await requestAndIssue(sid);
   const pending=await queue(sid,fresh.keys);
   assert.equal(pending.statusCode,201);
   const competitors=await Promise.all(Array.from({length:5},()=>processOneJob()));
   assert.equal(competitors.filter(Boolean).length,1);
   assert.equal((await receipts(pending.json().id as string)).length,fresh.keys.length);
  });
  await t.test("cross-tenant RLS on scope, permit, ledger, receipt, immutable audit and report",async()=>{
   const names=["api_pt_scopes","api_pt_permits","api_pt_ledger","api_pt_receipts","api_pt_reports","api_pt_events"];
   for(const name of names){
    const x=await withTenant(OTHER,tx=>tx.query("SELECT count(*)::int AS n FROM "+name));
    assert.equal(x.rows[0].n,0,name);
   }
   const reports=await withTenant(TENANT,tx=>tx.query("SELECT count(*)::int AS n FROM api_pt_reports"));
   assert.ok(reports.rows[0].n>=3);
  });
 }finally{await app.close();await pool.end();await workerPool.end();}
});
