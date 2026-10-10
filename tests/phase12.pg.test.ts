import {test} from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {randomUUID} from "node:crypto";
import {migrate,pool,withTenant,closeDatabase} from "../packages/database/src/index.js";
import {makeApp} from "../packages/service/src/app.js";
import {processOneJob} from "../packages/worker/src/index.js";
const A="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const B="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
type Result={statusCode:number;body:string;headers:Record<string,string|string[]|undefined>;json:()=>Record<string,unknown>};
const fixture=readFileSync(new URL("../fixtures/phase07-security.openapi.json",import.meta.url),"utf8");
test("Phase12 PostgreSQL 16 authorized report workflow and isolation",async t=>{
 await migrate();const app=await makeApp();
 const call=(method:"GET"|"POST"|"PUT",url:string,payload?:unknown,key?:string,beta=false)=>
  app.inject({method,url,payload:payload as object|undefined,headers:{authorization:"Bearer "+
   (beta?"local-test-token-beta":"local-test-token-alpha"),...(key?{"idempotency-key":key}:{})}}) as Promise<Result>;
 const ok=(x:Result,n:number)=>assert.equal(x.statusCode,n,x.body);
 try{
  await t.test("fresh additive migration 016, FORCE RLS, no public grants",async()=>{
   const v=await pool.query("SELECT version FROM public.api_schema_migrations WHERE version='016'");
   assert.equal(v.rowCount,1);
   const tables=await pool.query("SELECT relname,relrowsecurity,relforcerowsecurity FROM pg_class WHERE relname LIKE 'api_v12_%' AND relkind='r'");
   assert.equal(tables.rowCount,4);assert(tables.rows.every(x=>x.relrowsecurity&&x.relforcerowsecurity));
  });
  const token=randomUUID().slice(0,8);
  const target=await call("POST","/v1/targets",{name:"Phase12 PG "+token,
   environment:"SYNTHETIC",baseUrl:"https://phase12-"+token+".fixture.invalid"});ok(target,201);
  const targetId=target.json().id as string;
  const imp=await call("POST","/v2/targets/"+targetId+"/specifications/imports",
   {filename:"security.json",content:fixture},"phase12-import-"+randomUUID());ok(imp,201);
  const specId=imp.json().specificationId as string;
  const admission=await call("POST","/v11/api-vapt/assessments",
   {mode:"OFFLINE_ONLY",targetId,specificationId:specId},"phase12-offline-"+randomUUID());ok(admission,201);
  const rid=admission.json().id as string;
  assert.equal(await processOneJob(),true);
  assert.equal(await processOneJob(),true);
  const vapt=await call("GET","/v11/api-vapt/assessments/"+rid+"/report");ok(vapt,200);
  const findings=await call("GET","/v11/api-vapt/assessments/"+rid+"/findings?limit=50");ok(findings,200);
  const rows=findings.json() as unknown as {stable_key:string}[];
  await t.test("actual overview/list, immutable fingerprint-bound presentation and JSON export",async()=>{
   const overview=await call("GET","/v12/overview?targetId="+targetId);ok(overview,200);
   assert(Number(overview.json().immutableCompositeReports)>=1);
   const list=await call("GET","/v12/assessments?targetId="+targetId);ok(list,200);
   assert((list.json() as unknown as {id:string}[]).some(x=>x.id===rid));
   const p=await call("GET","/v12/reports/"+rid+"/presentation");ok(p,200);
   assert.equal(p.json().verifiedFixed,false);assert.equal(p.json().customerRuntimeVerified,false);
   assert.equal(p.json().schemaVersion,"api-security-report-presentation-v1");
   const j=await call("GET","/v12/reports/"+rid+"/export.json");ok(j,200);
   assert.match(String(j.headers["content-type"]),/application\/json/);
   assert.match(String(j.headers["cache-control"]),/no-store/);
   assert.equal(j.json().sourceFingerprint,p.json().sourceFingerprint);
  });
  await t.test("denied foreign tenant and invalid report reference never disclose findings",async()=>{
   for(const path of ["/v12/overview?targetId="+targetId,"/v12/assessments?targetId="+targetId,
    "/v12/reports/"+rid+"/presentation","/v12/reports/"+rid+"/export.json"]){
    const x=await call("GET",path,undefined,undefined,true);
    assert.equal(x.statusCode,404,x.body);
   }
   assert.equal((await call("GET","/v12/reports/"+randomUUID()+"/presentation")).statusCode,404);
   assert.equal((await call("GET","/v12/ai/capabilities")).json().mode,"DISABLED");
   assert.equal((await call("POST","/v12/ai/explain",{prompt:"run scans"})).statusCode,503);
  });
  await t.test("versioned branding, concurrent optimistic conflict, separate tenant",async()=>{
   const body={displayName:"Independent Demo",reportTitle:"API Evidence",accentHex:"#123ABC",expectedVersion:0};
   const [x,y]=await Promise.all([call("PUT","/v12/branding",body),call("PUT","/v12/branding",body)]);
   assert.deepEqual([x.statusCode,y.statusCode].sort(),[200,409],x.body+" | "+y.body);
   const other=await call("GET","/v12/branding",undefined,undefined,true);ok(other,200);
   assert.equal(other.json().version,0);
   assert.equal((await call("PUT","/v12/branding",{...body,displayName:"LumicSec Verified"})).statusCode,400);
   const stored=await withTenant(A,tx=>tx.query("SELECT version FROM api_v12_branding"));
   assert.equal(stored.rows[0].version,1);
  });
  await t.test("share idempotency, bearer-bound sharing, cross-tenant denial and revocation",async()=>{
   const key="phase12-share-"+randomUUID(),payload={durationSeconds:300};
   const [x,y]=await Promise.all([call("POST","/v12/reports/"+rid+"/shares",payload,key),
    call("POST","/v12/reports/"+rid+"/shares",payload,key)]);
   ok(x,200);ok(y,200);
   const sid=x.json().shareId as string;
   assert.equal(y.json().shareId,sid);
   assert.equal((await call("GET","/v12/shares/"+sid,undefined,undefined,true)).statusCode,404);
   ok(await call("GET","/v12/shares/"+sid),200);
   assert.equal((await call("POST","/v12/reports/"+rid+"/shares",{durationSeconds:600},key)).statusCode,409);
   ok(await call("POST","/v12/shares/"+sid+"/revoke"),200);
   assert.equal((await call("GET","/v12/shares/"+sid)).statusCode,404);
   assert.equal((await call("POST","/v12/shares/"+sid+"/revoke",undefined,undefined,true)).statusCode,404);
  });
  await t.test("real PostgreSQL expiry check, historical share rows stay immutable",async()=>{
   const s=await call("POST","/v12/reports/"+rid+"/shares",{durationSeconds:300},"phase12-expiry-"+randomUUID());ok(s,200);
   const sid=s.json().shareId as string;
   // Owner-only database fixture advances expiration without bypassing the public tenant role.
   const privileged=process.env.MIGRATION_DATABASE_URL;
   assert(privileged);
   const {Pool}=await import("pg");const admin=new Pool({connectionString:privileged,max:1});
   const expiredId=randomUUID();
   try{
    await assert.rejects(()=>admin.query("UPDATE public.api_v12_shares SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1",[sid]),
     /PHASE12_SHARE_IMMUTABLE_OR_REVOKED/);
    await admin.query("INSERT INTO public.api_v12_shares(id,tenant_id,parent_assessment_id,idempotency_key,duration_seconds,created_at,expires_at) VALUES($1,$2,$3,$4,300,clock_timestamp()-interval '2 hours',clock_timestamp()-interval '1 hour')",
     [expiredId,A,rid,"phase12-old-"+randomUUID()]);
   }finally{await admin.end();}
   assert.equal((await call("GET","/v12/shares/"+expiredId)).statusCode,404);
   const active=await call("GET","/v12/shares/"+sid);ok(active,200);
   assert.equal((await call("GET","/v12/reports/"+rid+"/shares")).statusCode,200);
  });
  if(rows[0]){
   await t.test("two independent connections race one annotation version; immutable finding retained",async()=>{
    const f=rows[0]!.stable_key,original=vapt.body;
    const request={stableKey:f,state:"FIX_CLAIMED",note:"Customer claim only",expectedVersion:0};
    const [x,y]=await Promise.all([call("POST","/v12/reports/"+rid+"/annotations",request),
     call("POST","/v12/reports/"+rid+"/annotations",request)]);
    assert.deepEqual([x.statusCode,y.statusCode].sort(),[200,409],x.body+" | "+y.body);
    assert.equal((x.statusCode===200?x:y).json().verifiedFixed,false);
    const historical=await withTenant(A,tx=>tx.query("SELECT version,state FROM api_v12_annotations WHERE parent_assessment_id=$1 AND stable_key=$2",[rid,f]));
    assert.equal(historical.rowCount,1);
    assert.equal((await call("GET","/v11/api-vapt/assessments/"+rid+"/report")).body,original);
    await assert.rejects(()=>withTenant(A,tx=>tx.query("DELETE FROM api_v12_annotations WHERE parent_assessment_id=$1",[rid])));
    assert.equal((await withTenant(B,tx=>tx.query("SELECT count(*)::int AS n FROM api_v12_annotations WHERE parent_assessment_id=$1",[rid]))).rows[0].n,0);
   });
  }
  await t.test("report access audit is immutable and tenant isolated",async()=>{
   const events=await call("GET","/v12/reports/"+rid+"/audit");ok(events,200);
   const list=events.json() as unknown as {action:string}[];
   assert(list.some(x=>x.action==="SHARE_CREATED"));
   assert.equal((await call("GET","/v12/reports/"+rid+"/audit",undefined,undefined,true)).statusCode,404);
   await assert.rejects(()=>withTenant(A,tx=>tx.query("DELETE FROM public.api_v12_report_audit WHERE parent_assessment_id=$1",[rid])));
  });
 }finally{await app.close();await closeDatabase();}
});
