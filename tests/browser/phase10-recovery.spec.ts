import {test,expect,type APIRequestContext,type Page} from "@playwright/test";
import {readFileSync} from "node:fs";
import {randomUUID} from "node:crypto";
import {spawn} from "node:child_process";
import {claimJob,withWorkerTenant,withTenant,finishWorkerAttempt,closeDatabase} from "../../packages/database/src/index.js";
import {processOneJob} from "../../packages/worker/src/index.js";
import {processPtOrchestrationJob} from "../../packages/worker/src/pt-orchestrator.js";
import {scheduleConservativeRetry} from "../../packages/worker/src/safety-retry.js";

const API="http://127.0.0.1:3001",A="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const tenant={authorization:"Bearer local-test-token-alpha"};
const other={authorization:"Bearer local-test-token-beta"};
const issuer={...tenant,"x-pt-authority-key":process.env.PT_TEST_AUTHORITY_KEY??""};
const source=readFileSync(new URL("../../fixtures/phase07-security.openapi.json",import.meta.url),"utf8");
test.afterAll(async()=>{await closeDatabase();});

async function seed(request:APIRequestContext,budget=4){
 const suffix=randomUUID().slice(0,8);
 const target=await request.post(API+"/v1/targets",{headers:tenant,
  data:{name:"Phase10 recovery "+suffix,environment:"SYNTHETIC",
   baseUrl:"https://p10-recovery-"+suffix+".fixture.invalid"}});
 expect(target.status(),await target.text()).toBe(201);
 const tid=(await target.json() as {id:string}).id;
 const imported=await request.post(API+"/v2/targets/"+tid+"/specifications/imports",{
  headers:{...tenant,"idempotency-key":"p10-recovery-import-"+randomUUID()},
  data:{filename:"phase07-security.openapi.json",content:source}});
 expect(imported.status(),await imported.text()).toBe(201);
 const specId=(await imported.json() as {specificationId:string}).specificationId;
 const operations=await request.get(API+"/v2/specifications/"+specId+"/operations?limit=100",{headers:tenant});
 expect(operations.status()).toBe(200);
 const ops=await operations.json() as {key:string;path:string;method:string}[];
 const keys=["/pt/account","/pt/resources/bob","/pt/admin","/pt/confidential"].map(path=>{
  const key=ops.find(x=>x.method==="GET"&&x.path===path)?.key;
  expect(key).toBeTruthy();return key;
 });
 const scoped=await request.post(API+"/v6/pt/targets/"+tid+"/scopes",{
  headers:{...tenant,"idempotency-key":"p10-recovery-scope-"+randomUUID()},
  data:{specificationId:specId,operationKeys:keys,fixtureId:"pt-security-v1",exclusions:[],
   maxEvaluations:budget,ratePerMinute:budget,maxConcurrency:1,deadlineMs:30000,validityMinutes:15}});
 expect(scoped.status(),await scoped.text()).toBe(201);
 const scopeId=(await scoped.json() as {id:string}).id;
 expect((await request.post(API+"/v6/pt/scopes/"+scopeId+"/request-authorization",{headers:tenant,data:{}})).status()).toBe(201);
 const permit=await request.post(API+"/v6/pt/test-authority/scopes/"+scopeId+"/issue",{headers:issuer,data:{}});
 expect(permit.status(),await permit.text()).toBe(201);
 return {tid,scopeId,permitId:(await permit.json() as {id:string}).id};
}
async function start(page:Page,request:APIRequestContext,tid:string,scopeId:string){
 await page.goto("/");
 await page.getByLabel("Select target").selectOption(tid);
 const panel=page.getByRole("region",{name:"Autonomous API security orchestration"});
 await expect(panel.getByText("REAL CUSTOMER API TESTING NOT AUTHORIZED")).toBeVisible();
 await expect(panel.getByText("WORKER RECOVERY DOES NOT GRANT NEW SECURITY AUTHORITY")).toBeVisible();
 await panel.getByLabel("Approved synthetic scope").selectOption(scopeId);
 await panel.getByLabel("Trusted policy profile").selectOption("SYNTHETIC_PT_AUTHORIZATION_FOCUSED");
 await expect(panel.getByText("Authorization readiness: VALID",{exact:false})).toBeVisible();
 await expect(panel.getByText("Immutable execution plan preview")).toBeVisible();
 await panel.getByRole("button",{name:"Start authorized orchestration"}).click();
 await expect(panel.getByText("Persisted orchestration progress")).toBeVisible();
 const history=await request.get(API+"/v9/pt/targets/"+tid+"/history",{headers:tenant});
 expect(history.status()).toBe(200);
 const jobs=await history.json() as {id:string}[];
 expect(jobs.length).toBeGreaterThan(0);
 return {jid:jobs[0]!.id,panel};
}
const safety=async(request:APIRequestContext,id:string)=>{
 const r=await request.get(API+"/v10/workers/assessments/"+id+"/execution",{headers:tenant});
 expect(r.status(),await r.text()).toBe(200);
 return r.json() as Promise<{attempts:{state:string;claim_generation:number}[];
  quarantine:{reason_code:string}|null;queue:{queueState:string}|null;
  events:{kind:string}[];assessment:{status:string}}>;
};

test("Phase10 Chromium B: OS SIGKILL after real governed checkpoint, safe recovery and visible worker attempts",async({page,request})=>{
 test.setTimeout(150000);
 const outbound:string[]=[];
 page.on("request",req=>{if(req.url().includes(".fixture.invalid"))outbound.push(req.url());});
 const {tid,scopeId,permitId}=await seed(request);
 const {jid,panel}=await start(page,request,tid,scopeId);
 const child=spawn(process.execPath,["--import","tsx","tests/helpers/phase10-pt-process.ts","after-checkpoint"],
  {env:process.env,stdio:["ignore","pipe","pipe","ipc"]});
 try{
  const event=await new Promise<{kind:string;claim:{assessment_id:string}}>((resolve,reject)=>{
   const timeout=setTimeout(()=>reject(new Error("CHROMIUM_REAL_CRASH_CHECKPOINT_TIMEOUT")),15000);
   child.once("message",value=>{clearTimeout(timeout);resolve(value as {kind:string;claim:{assessment_id:string}});});
   child.once("error",reject);
   child.once("exit",code=>{clearTimeout(timeout);reject(new Error("CHILD_EXIT_BEFORE_CHECKPOINT_"+code));});
  });
  expect(event.kind).toBe("after-checkpoint");
  expect(event.claim.assessment_id).toBe(jid);
  const exited=new Promise<NodeJS.Signals|null>(resolve=>child.once("exit",(_code,signal)=>resolve(signal)));
  child.kill("SIGKILL");
  expect(await exited).toBe("SIGKILL");
  await withWorkerTenant(A,tx=>tx.query("UPDATE api_queue.api_assessment_queue SET locked_until=clock_timestamp()-interval '1 second' WHERE assessment_id=$1",[jid]));
  expect(await processOneJob()).toBe(true);
  await expect(panel.getByText("Immutable completed synthetic report")).toBeVisible({timeout:30000});
  const attempts=await safety(request,jid);
  expect(attempts.attempts.map(x=>x.state)).toEqual(["COMPLETED","LOST"]);
  await expect(panel.getByText("Generation 1 · LOST",{exact:false})).toBeVisible();
  await expect(panel.getByText("Generation 2 · COMPLETED",{exact:false})).toBeVisible();
  const p=await withTenant(A,tx=>tx.query("SELECT consumed,reserved FROM api_pt_permits WHERE id=$1",[permitId]));
  expect(p.rows[0].consumed).toBe(4);
  expect(p.rows[0].reserved).toBe(0);
  expect(outbound).toEqual([]);
 }finally{if(child.exitCode===null&&!child.killed)child.kill("SIGKILL");}
});

test("Phase10 Chromium C: cancellation after one evaluated rule leaves truthful terminal and CANCELLED attempt",async({page,request})=>{
 test.setTimeout(150000);
 const {tid,scopeId}=await seed(request);
 const {jid,panel}=await start(page,request,tid,scopeId);
 const claim=await claimJob();expect(claim?.assessment_id).toBe(jid);
 await processPtOrchestrationJob(A,jid,claim!.claim_token,{afterEvaluation:async n=>{
  if(n===1){
   const cancelled=await request.post(API+"/v9/pt/orchestrations/"+jid+"/cancel",{headers:tenant,data:{}});
   expect(cancelled.status(),await cancelled.text()).toBe(200);
  }
 }});
 await finishWorkerAttempt(claim!);
 await expect(panel.getByText("Terminal diagnostic — not a successful PT report")).toBeVisible({timeout:30000});
 const a=await safety(request,jid);
 expect(a.assessment.status).toBe("CANCELLED");
 expect(a.attempts[0]?.state).toBe("CANCELLED");
 expect((await request.get(API+"/v9/pt/orchestrations/"+jid+"/report",{headers:tenant})).status()).toBe(409);
 expect((await request.get(API+"/v9/pt/orchestrations/"+jid+"/terminal",{headers:tenant})).status()).toBe(200);
});

test("Phase10 Chromium D: replaced worker's stale heartbeat and deletion fail while new generation finishes",async({page,request})=>{
 test.setTimeout(150000);
 const {tid,scopeId,permitId}=await seed(request);
 const {jid,panel}=await start(page,request,tid,scopeId);
 const first=await claimJob();expect(first?.assessment_id).toBe(jid);
 await withWorkerTenant(A,tx=>tx.query("UPDATE api_queue.api_assessment_queue SET locked_until=clock_timestamp()-interval '1 second' WHERE assessment_id=$1",[jid]));
 const second=await claimJob();expect(second?.assessment_id).toBe(jid);
 expect(second?.claim_generation).toBe(2);
 const {renewWorkerClaim}=await import("../../packages/database/src/index.js");
 expect(await renewWorkerClaim(first!)).toBe(false);
 const denied=await withWorkerTenant(A,tx=>tx.query(
  "DELETE FROM api_queue.api_assessment_queue WHERE assessment_id=$1 AND claim_token=$2 AND claim_generation=$3",
  [jid,first!.claim_token,first!.claim_generation]));
 expect(denied.rowCount).toBe(0);
 await processPtOrchestrationJob(A,jid,second!.claim_token);
 await finishWorkerAttempt(second!);await finishWorkerAttempt(first!);
 await expect(panel.getByText("Immutable completed synthetic report")).toBeVisible({timeout:30000});
 const a=await safety(request,jid);
 expect(a.attempts.map(x=>x.state)).toEqual(["COMPLETED","LOST"]);
 const p=await withTenant(A,tx=>tx.query("SELECT consumed,reserved FROM api_pt_permits WHERE id=$1",[permitId]));
 expect(p.rows[0].consumed).toBe(4);expect(p.rows[0].reserved).toBe(0);
});

test("Phase10 Chromium E: genuine pre-execution infrastructure retry exhausts and shows terminal quarantine",async({page,request})=>{
 test.setTimeout(150000);
 const {tid,scopeId}=await seed(request);
 const {jid,panel}=await start(page,request,tid,scopeId);
 for(let n=0;n<4;n++){
  const claim=await claimJob();expect(claim?.assessment_id).toBe(jid);
  const decision=await scheduleConservativeRetry(claim!,{code:"08006"});
  expect(decision).toBe(n===3?"RETRY_EXHAUSTED":"RETRY_SCHEDULED");
  if(n<3)await withWorkerTenant(A,tx=>tx.query(
   "UPDATE api_queue.api_assessment_queue SET next_eligible_at=clock_timestamp()-interval '1 second' WHERE assessment_id=$1",[jid]));
 }
 await expect(panel.getByText("Terminal quarantine: WORKER_RETRY_EXHAUSTED",{exact:false})).toBeVisible({timeout:30000});
 await expect(panel.getByText("Terminal diagnostic — not a successful PT report")).toBeVisible();
 const a=await safety(request,jid);
 expect(a.quarantine?.reason_code).toBe("WORKER_RETRY_EXHAUSTED");
 expect(a.attempts).toHaveLength(4);
 expect(a.attempts.every(x=>x.state==="FAILED")).toBe(true);
 expect((await request.get(API+"/v9/pt/orchestrations/"+jid+"/report",{headers:tenant})).status()).toBe(409);
});

test("Phase10 Chromium F: emergency stop cancels queued work, UI reflects stop, no permit bypass",async({page,request})=>{
 test.setTimeout(150000);
 const {tid,scopeId}=await seed(request);
 const {jid,panel}=await start(page,request,tid,scopeId);
 try{
  const stop=await request.post(API+"/v6/pt/test-authority/stop",{headers:issuer,data:{}});
  expect(stop.status(),await stop.text()).toBe(200);
  await panel.getByRole("button",{name:"Refresh history"}).click();
  await expect(panel.getByText("Emergency stop: ACTIVE — admission blocked")).toBeVisible({timeout:30000});
  await expect(panel.getByText("Terminal diagnostic — not a successful PT report")).toBeVisible({timeout:30000});
  const a=await safety(request,jid);
  expect(a.assessment.status).toBe("CANCELLED");
  expect((await request.get(API+"/v9/pt/orchestrations/"+jid+"/report",{headers:tenant})).status()).toBe(409);
 }finally{
  const resume=await request.post(API+"/v6/pt/test-authority/resume",{headers:issuer,data:{}});
  expect(resume.status(),await resume.text()).toBe(200);
 }
});

test("Phase10 Chromium G: worker attempt/quarantine/status are tenant-private with no control leakage",async({page,request})=>{
 test.setTimeout(150000);
 const {tid,scopeId}=await seed(request);
 const {jid,panel}=await start(page,request,tid,scopeId);
 expect(await processOneJob()).toBe(true);
 await expect(panel.getByText("Worker safety, recovery and attempt history")).toBeVisible({timeout:30000});
 const a=await safety(request,jid);
 expect(a.attempts).toHaveLength(1);
 const foreign=await request.get(API+"/v10/workers/assessments/"+jid+"/execution",{headers:other});
 expect(foreign.status()).toBe(404);
 const foreignStatus=await request.get(API+"/v9/pt/orchestrations/"+jid,{headers:other});
 expect(foreignStatus.status()).toBe(404);
 const foreignCancel=await request.post(API+"/v9/pt/orchestrations/"+jid+"/cancel",{headers:other,data:{}});
 expect([403,404,409]).toContain(foreignCancel.status());
 const check=await safety(request,jid);
 expect(check.assessment.status).toBe("COMPLETED");
});
