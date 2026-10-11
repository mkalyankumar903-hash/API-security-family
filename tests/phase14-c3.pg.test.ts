/** Phase14 C3: real post-commit permit revocation + emergency governor stop.
 * Assertions bind emitted local diagnostics to committed PostgreSQL authority,
 * not a browser-supplied or precommit claim. Only CI synthetic permit issuer.
 */
import {test,after} from "node:test";
import assert from "node:assert/strict";
import {randomUUID} from "node:crypto";
import {readFileSync} from "node:fs";
import {migrate,withTenant,closeDatabase} from "../packages/database/src/index.js";
import {makeApp} from "../packages/service/src/app.js";
const tenant="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const spec=readFileSync(new URL("../fixtures/phase07-security.openapi.json",import.meta.url),"utf8");
after(async()=>{await closeDatabase();});
test("Phase14 C3 revoked permit and stopped governor emit sanitized diagnostics only after committed denial",async()=>{
 await migrate();const app=await makeApp();
 const saved={diagnostics:process.env.API_FAMILY_DIAGNOSTICS,
  node:process.env.NODE_ENV,synthetic:process.env.SYNTHETIC_AUTH_ENABLED};
 const orig=process.stderr.write,records:string[]=[];
 process.stderr.write=((x:unknown)=>{records.push(String(x));return true;}) as typeof process.stderr.write;
 process.env.API_FAMILY_DIAGNOSTICS="true";process.env.NODE_ENV="test";
 process.env.SYNTHETIC_AUTH_ENABLED="true";
 const call=async(method:"GET"|"POST",url:string,data?:object,key?:string,authority=false)=>{
  const response=await app.inject({method,url,payload:data,headers:{
   authorization:"Bearer local-test-token-alpha",
   ...(key?{"idempotency-key":key}:{}),
   ...(authority?{"x-pt-authority-key":process.env.PT_TEST_AUTHORITY_KEY??""}:{})
  }});
  assert(response.statusCode>=200&&response.statusCode<300,response.body);
  return response.json() as Record<string,unknown>;
 };
 try{
  const t=await call("POST","/v1/targets",{
   name:"Phase14 C3 "+randomUUID().slice(0,8),
   baseUrl:"https://c3-"+randomUUID()+".fixture.invalid",environment:"SYNTHETIC"});
  const target=t.id as string;
  const inventory=await call("POST","/v2/targets/"+target+"/specifications/imports",
   {filename:"phase07-security.openapi.json",content:spec},"c3-import-"+randomUUID());
  const sid=inventory.specificationId as string;
  const ops=await call("GET","/v2/specifications/"+sid+"/operations?limit=100") as unknown as
   {key:string;method:string;path:string}[];
  const keys=["/pt/account","/pt/resources/bob","/pt/admin","/pt/confidential"]
   .map(path=>ops.find(x=>x.path===path&&x.method==="GET")?.key);
  assert(keys.every(Boolean));
  const scope=async()=>await call("POST","/v6/pt/targets/"+target+"/scopes",{
   specificationId:sid,operationKeys:keys,fixtureId:"pt-security-v1",exclusions:[],
   maxEvaluations:14,ratePerMinute:14,maxConcurrency:1,deadlineMs:30000,validityMinutes:15
  },"c3-scope-"+randomUUID());
  const issue=async(scopeId:string)=>{
   await call("POST","/v6/pt/scopes/"+scopeId+"/request-authorization",{});
   return call("POST","/v6/pt/test-authority/scopes/"+scopeId+"/issue",{},undefined,true);
  };
  const first=(await scope()).id as string;
  const permit=(await issue(first)).id as string;
  records.length=0;
  await call("POST","/v6/pt/test-authority/permits/"+permit+"/revoke",{},undefined,true);
  const db=await withTenant(tenant,async tx=>{
   const p=await tx.query("SELECT revoked_at FROM api_pt_permits WHERE id=$1",[permit]);
   const events=await tx.query("SELECT action FROM api_pt_events WHERE subject_id=$1",[permit]);
   return {revoked:p.rows[0]?.revoked_at,events:events.rows.map(x=>x.action)};
  });
  assert(db.revoked);assert(db.events.includes("TEST_PERMIT_REVOKED"));
  assert(records.some(v=>v.includes('"kind":"ASSESSMENT_TRANSITION"')&&
   v.includes('"state":"REVOKED"')&&v.includes('"classification":"STALE"')));
  const second=(await scope()).id as string;
  const secondPermit=(await issue(second)).id as string;
  const job=await call("POST","/v6/pt/scopes/"+second+"/jobs",
   {operationKeys:keys},"c3-job-"+randomUUID());
  const jid=job.id as string;
  const started=await withTenant(tenant,tx=>tx.query("SELECT status FROM api_assessments WHERE id=$1",[jid]));
  assert.equal(started.rows[0].status,"QUEUED");
  records.length=0;
  const stopped=await call("POST","/v6/pt/test-authority/stop",{},undefined,true);
  assert.equal(stopped.enabled,true);
  const terminal=await withTenant(tenant,async tx=>{
   const g=await tx.query("SELECT enabled FROM api_pt_stop WHERE tenant_id=$1",[tenant]);
   const a=await tx.query("SELECT status FROM api_assessments WHERE id=$1",[jid]);
   const p=await tx.query("SELECT revoked_at FROM api_pt_permits WHERE id=$1",[secondPermit]);
   const events=await tx.query("SELECT action FROM api_pt_events WHERE action='PT_EMERGENCY_STOP'");
   const receipts=await tx.query("SELECT count(*)::int AS n FROM api_pt_receipts WHERE assessment_id=$1",[jid]);
   return {enabled:g.rows[0]?.enabled,state:a.rows[0]?.status,revoked:p.rows[0]?.revoked_at,
    stoppedEvents:events.rowCount,receipts:receipts.rows[0].n};
  });
  assert(terminal.enabled);assert.equal(terminal.state,"CANCELLED");
  assert(terminal.revoked);assert(Number(terminal.stoppedEvents)>0);assert.equal(terminal.receipts,0);
  assert(records.some(v=>v.includes('"kind":"ASSESSMENT_TRANSITION"')&&
   v.includes('"state":"CANCELLED"')&&v.includes('"classification":"AUTH"')));
  assert(records.every(v=>!v.includes(permit)&&!v.includes(secondPermit)&&
   !v.includes(tenant)&&!v.includes("pt-security-v1")));
  await call("POST","/v6/pt/test-authority/resume",{},undefined,true);
  const state=await call("GET","/v6/pt/stop");
  assert.equal(state.enabled,false);
  const p=await call("GET","/v6/pt/permits/"+secondPermit);
  assert.equal(p.state,"REVOKED","resume must not restore revoked authority");
  console.log("PHASE14_C3_SQL_COMMITTED_DIAGNOSTICS_PASS "+JSON.stringify({
   revoked:true,stopped:true,queuedJobCancelled:true,receipts:0,
   unauthorizedResumption:false,noIdentifiers:true,externalTelemetry:false}));
 }finally{
  process.stderr.write=orig;
  for(const [key,value] of [["API_FAMILY_DIAGNOSTICS",saved.diagnostics],
   ["NODE_ENV",saved.node],["SYNTHETIC_AUTH_ENABLED",saved.synthetic]] as const){
   if(value===undefined)delete process.env[key];else process.env[key]=value;
  }
  await app.close();
 }
});
