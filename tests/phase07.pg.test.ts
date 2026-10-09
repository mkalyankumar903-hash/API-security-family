import {test} from "node:test";
import assert from "node:assert/strict";
import {randomUUID} from "node:crypto";
import {readFileSync} from "node:fs";
import {makeApp} from "../packages/service/src/app.js";
import {migrate,pool,withTenant,withWorkerTenant,closeDatabase} from "../packages/database/src/index.js";
import {processOneJob,drainQueue} from "../packages/worker/src/index.js";
import {RULES} from "../packages/pt/src/detection.js";
const A="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",B="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const AUTH="local-test-token-alpha",SIGNER=process.env.PT_TEST_AUTHORITY_KEY??"";
const source=readFileSync(new URL("../fixtures/phase07-security.openapi.json",import.meta.url),"utf8");
type API={statusCode:number;body:string;json:()=>Record<string,unknown>};
test("Phase07 real PostgreSQL 16 — governed synthetic detection, RLS and preservation",async t=>{
 await migrate();
 const app=await makeApp();
 async function call(method:"GET"|"POST",url:string,payload?:unknown,opts?:{token?:string;key?:string;authority?:boolean}):Promise<API>{
  return app.inject({method,url,payload:payload as object|undefined,headers:{
   authorization:"Bearer "+(opts?.token??AUTH),...(opts?.key?{"idempotency-key":opts.key}:{}),
   ...(opts?.authority?{"x-pt-authority-key":SIGNER}:{})
  }});
 }
 async function seed(){
  const unique=randomUUID().slice(0,8);
  const r=await call("POST","/v1/targets",{name:"PT7-"+unique,environment:"SYNTHETIC",baseUrl:"https://pt7-"+unique+".fixture.invalid"});
  assert.equal(r.statusCode,201,r.body);const targetId=r.json().id as string;
  const i=await call("POST","/v2/targets/"+targetId+"/specifications/imports",
   {filename:"phase07-security.openapi.json",content:source},{key:"pt7-import-"+randomUUID()});
  assert.equal(i.statusCode,201,i.body);const specId=i.json().specificationId as string;
  const o=await call("GET","/v2/specifications/"+specId+"/operations?limit=100");
  assert.equal(o.statusCode,200,o.body);
  const ops=o.json() as unknown as {key:string;path:string;method:string}[];
  const keys=ops.filter(x=>x.method==="GET"&&x.path.startsWith("/pt/")).map(x=>x.key);
  assert.equal(keys.length,4);
  return {targetId,specId,keys};
 }
 async function scope(s:Awaited<ReturnType<typeof seed>>,rules=RULES.map(x=>x.id)){
  const paths=new Set<string>(RULES.filter(x=>rules.includes(x.id)).map(x=>x.path));
  const ops=await call("GET","/v2/specifications/"+s.specId+"/operations?limit=100");
  const keys=(ops.json() as unknown as {key:string;path:string;method:string}[])
   .filter(x=>x.method==="GET"&&paths.has(x.path)).map(x=>x.key);
  const budget=RULES.filter(x=>rules.includes(x.id)).reduce((n,r)=>n+r.cases.length,0);
  const r=await call("POST","/v6/pt/targets/"+s.targetId+"/scopes",{
   specificationId:s.specId,operationKeys:keys,fixtureId:"pt-security-v1",exclusions:[],
   maxEvaluations:budget,ratePerMinute:20,maxConcurrency:1,deadlineMs:30000,validityMinutes:15
  },{key:"pt7-scope-"+randomUUID()});
  assert.equal(r.statusCode,201,r.body);return r.json().id as string;
 }
 async function permit(sid:string){
  assert.equal((await call("POST","/v6/pt/scopes/"+sid+"/request-authorization",{})).statusCode,201);
  assert.equal((await call("POST","/v6/pt/test-authority/scopes/"+sid+"/issue",{})).statusCode,403);
  const r=await call("POST","/v6/pt/test-authority/scopes/"+sid+"/issue",{}, {authority:true});
  assert.equal(r.statusCode,201,r.body);
  return r.json().id as string;
 }
 async function start(sid:string,profile:string,ruleIds:string[]=RULES.map(x=>x.id),key="pt7-job-"+randomUUID()){
  return call("POST","/v7/pt/scopes/"+sid+"/detections",{profile,ruleIds},{key});
 }
 try{
  await t.test("fresh 001-011 and FORCE RLS on all four Phase07 tables",async()=>{
   const v=await pool.query("SELECT count(*)::int AS n FROM api_schema_migrations WHERE version BETWEEN '001' AND '011'");
   assert.equal(v.rows[0].n,11);
   const r=await pool.query("SELECT relname,relrowsecurity,relforcerowsecurity FROM pg_class WHERE relname LIKE 'api_pt_detection_%' AND relkind='r'");
   assert.equal(r.rowCount,4);
   assert.ok(r.rows.every(x=>x.relrowsecurity&&x.relforcerowsecurity));
   const noContext=await pool.query("SELECT * FROM api_pt_detection_plans");
   assert.equal(noContext.rowCount,0,"Unscoped application principal sees zero tenant rows");
  });
  const s=await seed();
  await t.test("rule registry and fixture expose no customer destination",async()=>{
   const r=await call("GET","/v7/pt/rules"),x=await call("GET","/v7/pt/fixtures");
   assert.equal(r.statusCode,200);assert.equal(x.statusCode,200);
   assert.equal((r.json().rules as unknown[]).length,8);
   assert.equal((x.json().customerNetworkRequests as number),0);
  });
  const sid=await scope(s);
  await t.test("no permit, invalid rule and forged verdict are rejected",async()=>{
   const denied=await start(sid,"SECURE_BASELINE");assert.equal(denied.statusCode,409,denied.body);
   assert.equal(denied.json().error,"AUTHORIZATION_MISSING");
   assert.equal((await start(sid,"PRODUCTION")).statusCode,400);
   const unsupported=await start(sid,"SECURE_BASELINE",["PT-NONEXISTENT"]);
   assert.equal(unsupported.statusCode,400,unsupported.body);
   assert.equal(unsupported.json().error,"UNKNOWN_DETECTION_RULE");
   const fake=await call("POST","/v7/pt/scopes/"+sid+"/detections",
    {profile:"SECURE_BASELINE",ruleIds:[RULES[0]!.id],verdict:"CONFIRMED"},{key:"pt7-fake-"+randomUUID()});
   assert.equal(fake.statusCode,400);
   const other=await call("POST","/v7/pt/scopes/"+sid+"/detections",
    {profile:"SECURE_BASELINE",ruleIds:[RULES[0]!.id]},{token:"local-test-token-beta",key:"pt7-other-"+randomUUID()});
   assert.equal(other.statusCode,404);
  });
  const pid=await permit(sid);
  await t.test("v7 signed synthetic permit uses separate envelope and no MAC storage",async()=>{
   const row=await withTenant(A,tx=>tx.query("SELECT signed_body,token_hash,claims FROM api_pt_permits WHERE id=$1",[pid]));
   assert.equal(row.rows[0].claims.fixtureId,"pt-security-v1");
   assert.match(row.rows[0].token_hash,/^[0-9a-f]{64}$/);
   assert.ok(typeof row.rows[0].signed_body==="string");
   assert.equal(JSON.stringify(row.rows[0]).includes("pt7v1."),false);
  });
  const queued=await start(sid,"MISSING_AUTH_ENFORCEMENT");
  assert.equal(queued.statusCode,201,queued.body);
  const job=queued.json().id as string;
  await t.test("idempotent admission and real governed worker produces evidence-backed auth observations",async()=>{
   const idem="pt7-same-"+randomUUID();
   const r=await start(await (async()=>{const other=await scope(s);await permit(other);return other;})(),"SECURE_BASELINE",RULES.map(x=>x.id),idem);
   assert.equal(r.statusCode,201,r.body);
   assert.equal((await start((await call("GET","/v7/pt/jobs/"+(r.json().id as string))).json().scope_id as string,"SECURE_BASELINE",RULES.map(x=>x.id),idem)).statusCode,200);
   assert.equal(await drainQueue(2),2);
   const detail=await call("GET","/v7/pt/jobs/"+job);
   assert.equal(detail.statusCode,200,detail.body);assert.equal(detail.json().status,"COMPLETED");
   const report=await call("GET","/v7/pt/jobs/"+job+"/report");
   assert.equal(report.statusCode,200,report.body);
   const summary=report.json() as {observations:unknown[];coverage:{actualEvaluations:number};customerNetworkRequests:number;verifiedFixed:boolean};
   assert.equal(summary.observations.length,4);
   assert.equal(summary.coverage.actualEvaluations,14);
   assert.equal(summary.customerNetworkRequests,0);assert.equal(summary.verifiedFixed,false);
   const evals=await call("GET","/v7/pt/jobs/"+job+"/evaluations");
   const evidence=evals.json() as unknown as {evidence:{responseHash:string;exposedPaths:string[]}|null}[];
   assert.equal(evidence.length,14);
   assert.ok(evidence.every(x=>x.evidence?.responseHash.length===64));
   assert.equal(evals.body.includes("SYNTHETIC_PLACEHOLDER_NOT_A_SECRET"),false);
   const leaked=await call("GET","/v7/pt/jobs/"+job+"/report",undefined,{token:"local-test-token-beta"});
   assert.equal(leaked.statusCode,409,"RLS protected cross-tenant report must not exist");
   await assert.rejects(()=>withTenant(A,tx=>tx.query("UPDATE api_pt_detection_reports SET projection='{}'::jsonb WHERE assessment_id=$1",[job])),/immutable|permission denied|PHASE1/i);
   await assert.rejects(()=>withTenant(A,tx=>tx.query("UPDATE api_pt_detection_results SET status='PASS' WHERE assessment_id=$1",[job])),/immutable|permission denied|PHASE1/i);
   assert.equal((await withWorkerTenant(A,tx=>tx.query("SELECT count(*)::int AS n FROM api_pt_detection_evaluations WHERE assessment_id=$1 AND state='RESERVED'",[job]))).rows[0].n,0);
   const secureReport=await call("GET","/v7/pt/jobs/"+(r.json().id as string)+"/report");
   assert.equal(secureReport.statusCode,200,secureReport.body);
   assert.equal((secureReport.json().observations as unknown[]).length,0);
  });
  await t.test("permit exhaustion, immutable report and tenant isolation",async()=>{
   const r=await start(sid,"MISSING_AUTH_ENFORCEMENT");
   assert.equal(r.statusCode,409,r.body);assert.equal(r.json().error,"PERMIT_BUDGET_EXHAUSTED");
   const p=await withTenant(A,tx=>tx.query("SELECT consumed,reserved FROM api_pt_permits WHERE id=$1",[pid]));
   assert.equal(p.rows[0].consumed,14);assert.equal(p.rows[0].reserved,0);
   assert.equal((await withTenant(B,tx=>tx.query("SELECT count(*)::int AS n FROM api_pt_detection_results WHERE assessment_id=$1",[job]))).rows[0].n,0);
  });
  await t.test("revocation after queue admission denies subsequent fixture execution",async()=>{
   const fresh=await scope(s,[RULES[0]!.id]);const p=await permit(fresh);
   const run=await start(fresh,"MISSING_AUTH_ENFORCEMENT",[RULES[0]!.id]);
   assert.equal(run.statusCode,201,run.body);
   assert.equal((await call("POST","/v6/pt/test-authority/permits/"+p+"/revoke",{}, {authority:true})).statusCode,200);
   assert.equal(await processOneJob(),true);
   const detail=await call("GET","/v7/pt/jobs/"+(run.json().id as string));
   assert.equal(detail.json().status,"FAILED");
   assert.equal((await call("GET","/v7/pt/jobs/"+(run.json().id as string)+"/report")).statusCode,409);
  });
  await t.test("cancelled queued detection has no successful report or network interaction",async()=>{
   const fresh=await scope(s,[RULES[4]!.id]);await permit(fresh);
   const run=await start(fresh,"CROSS_USER_ACCESS_WEAKNESS",[RULES[4]!.id]);
   assert.equal(run.statusCode,201);
   const jid=run.json().id as string;
   assert.equal((await call("POST","/v6/pt/jobs/"+jid+"/cancel",{})).statusCode,200);
   assert.equal((await call("GET","/v7/pt/jobs/"+jid+"/report")).statusCode,409);
   assert.equal((await withTenant(A,tx=>tx.query("SELECT count(*)::int AS n FROM api_pt_detection_evaluations WHERE assessment_id=$1",[jid]))).rows[0].n,0);
  });
  await t.test("parallel idempotent PT7 admission owns exactly one queue item and enforces per-permit concurrency",async()=>{
   const fresh=await scope(s,[RULES[4]!.id]);await permit(fresh);
   const idem="pt7-parallel-"+randomUUID();
   const [one,two]=await Promise.all([
    start(fresh,"CROSS_USER_ACCESS_WEAKNESS",[RULES[4]!.id],idem),
    start(fresh,"CROSS_USER_ACCESS_WEAKNESS",[RULES[4]!.id],idem)
   ]);
   assert.deepEqual([one.statusCode,two.statusCode].sort((a,b)=>a-b),[200,201],one.body+" | "+two.body);
   const first=one.json().id as string,second=two.json().id as string;
   assert.equal(first,second,"parallel idempotent admissions must return the same immutable assessment");
   const queue=await withWorkerTenant(A,tx=>tx.query(
    "SELECT count(*)::int AS n FROM api_queue.api_assessment_queue WHERE assessment_id=$1",[first]));
   assert.equal(queue.rows[0].n,1,"no duplicate worker delivery was persisted");
   const rejected=await start(fresh,"CROSS_USER_ACCESS_WEAKNESS",[RULES[4]!.id]);
   assert.equal(rejected.statusCode,409,rejected.body);
   assert.equal(rejected.json().error,"CONCURRENCY_LIMIT");
   assert.equal(await drainQueue(1),1);
   const detail=await call("GET","/v7/pt/jobs/"+first);
   assert.equal(detail.json().status,"COMPLETED");
   const evals=await call("GET","/v7/pt/jobs/"+first+"/evaluations");
   assert.equal((evals.json() as unknown as unknown[]).length,2,"no duplicated governed evaluations");
   const report=await call("GET","/v7/pt/jobs/"+first+"/report");
   assert.equal((report.json().observations as unknown[]).length,1);
  });
  await t.test("signed-authority emergency stop cancels queued PT7 job without fixture execution or report",async()=>{
   const fresh=await scope(s,[RULES[0]!.id]);await permit(fresh);
   const queued=await start(fresh,"MISSING_AUTH_ENFORCEMENT",[RULES[0]!.id]);
   assert.equal(queued.statusCode,201,queued.body);
   const jid=queued.json().id as string;
   const forged=await call("POST","/v6/pt/test-authority/stop",{});
   assert.equal(forged.statusCode,403,forged.body);
   const stopped=await call("POST","/v6/pt/test-authority/stop",{}, {authority:true});
   assert.equal(stopped.statusCode,200,stopped.body);
   assert.equal((await call("GET","/v7/pt/jobs/"+jid)).json().status,"CANCELLED");
   assert.equal((await call("GET","/v7/pt/jobs/"+jid+"/report")).statusCode,409);
   const evaluations=await withTenant(A,tx=>tx.query(
    "SELECT count(*)::int AS n FROM api_pt_detection_evaluations WHERE assessment_id=$1",[jid]));
   assert.equal(evaluations.rows[0].n,0,"no execution permitted after emergency stop");
   const resumed=await call("POST","/v6/pt/test-authority/resume",{}, {authority:true});
   assert.equal(resumed.statusCode,200,resumed.body);
   const retry=await start(fresh,"MISSING_AUTH_ENFORCEMENT",[RULES[0]!.id]);
   assert.equal(retry.statusCode,409,retry.body);
   assert.equal(retry.json().error,"PERMIT_REVOKED","resume must never revive a revoked permit");
  });
 }finally{await app.close();await closeDatabase();}
});
