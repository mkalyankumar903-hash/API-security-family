import {test,expect,type APIRequestContext} from "@playwright/test";
import {readFileSync} from "node:fs";
import {randomUUID} from "node:crypto";
import {processOneJob} from "../../packages/worker/src/index.js";
import {closeDatabase} from "../../packages/database/src/index.js";
const API="http://127.0.0.1:3001";
const auth={"authorization":"Bearer local-test-token-alpha"};
const other={"authorization":"Bearer local-test-token-beta"};
const issuer={...auth,"x-pt-authority-key":process.env.PT_TEST_AUTHORITY_KEY??""};
const source=readFileSync(new URL("../../fixtures/phase07-security.openapi.json",import.meta.url),"utf8");
test.afterAll(async()=>{await closeDatabase();});
async function seed(request:APIRequestContext,issuePermit=true){
 const suffix=randomUUID().slice(0,8);
 const r=await request.post(API+"/v1/targets",{headers:auth,data:{
  name:"Phase11 Chromium "+suffix,environment:"SYNTHETIC",
  baseUrl:"https://pt11-"+suffix+".fixture.invalid"}});
 expect(r.status(),await r.text()).toBe(201);
 const tid=(await r.json() as {id:string}).id;
 const imported=await request.post(API+"/v2/targets/"+tid+"/specifications/imports",{
  headers:{...auth,"idempotency-key":"pt11-import-"+randomUUID()},
  data:{filename:"phase07-security.openapi.json",content:source}});
 expect(imported.status(),await imported.text()).toBe(201);
 const sid=(await imported.json() as {specificationId:string}).specificationId;
 const response=await request.get(API+"/v2/specifications/"+sid+"/operations?limit=100",{headers:auth});
 expect(response.status()).toBe(200);
 const operations=await response.json() as {key:string;path:string;method:string}[];
 const operationKeys=["/pt/account","/pt/resources/bob","/pt/admin","/pt/confidential"].map(path=>
  operations.find(x=>x.path===path&&x.method==="GET")?.key);
 expect(operationKeys.every(Boolean)).toBeTruthy();
 const scoped=await request.post(API+"/v6/pt/targets/"+tid+"/scopes",{
  headers:{...auth,"idempotency-key":"pt11-scope-"+randomUUID()},
  data:{specificationId:sid,operationKeys,fixtureId:"pt-security-v1",exclusions:[],
   maxEvaluations:14,ratePerMinute:14,maxConcurrency:1,deadlineMs:30000,validityMinutes:15}});
 expect(scoped.status(),await scoped.text()).toBe(201);
 const scopeId=(await scoped.json() as {id:string}).id;
 if(issuePermit){
  expect((await request.post(API+"/v6/pt/scopes/"+scopeId+"/request-authorization",{
   headers:auth,data:{}})).status()).toBe(201);
  const p=await request.post(API+"/v6/pt/test-authority/scopes/"+scopeId+"/issue",{
   headers:issuer,data:{}});
  expect(p.status(),await p.text()).toBe(201);
 }
 return {tid,sid,scopeId};
}
async function open(page:import("@playwright/test").Page,tid:string){
 await page.goto("/");
 await page.getByLabel("Select target").selectOption(tid);
 const panel=page.getByRole("region",{name:"Autonomous API VAPT workspace"});
 await expect(panel).toBeVisible();
 await expect(panel.getByText("ISOLATED SYNTHETIC AUTONOMOUS API VAPT")).toBeVisible();
 await expect(panel.getByText("NO CUSTOMER VULNERABILITY IS CONFIRMED BY SYNTHETIC FIXTURES")).toBeVisible();
 return panel;
}
/** One visible heading is static UI chrome, NOT proof of completed PostgreSQL admission.
 * Verify both the committed history identity and its authoritative parent+child status. */
async function admitted(request:APIRequestContext,tid:string,mode:"OFFLINE_ONLY"|"GOVERNED_SYNTHETIC"){
 await expect.poll(async()=>{
  const h=await request.get(API+"/v11/api-vapt/targets/"+tid+"/history",{headers:auth});
  if(h.status()!==200)return 0;
  const rows=await h.json() as {id:string;mode:string}[];
  return rows.filter(x=>x.mode===mode).length;
 },{timeout:20000,message:"Phase11 committed PostgreSQL parent admission"}).toBe(1);
 const r=await request.get(API+"/v11/api-vapt/targets/"+tid+"/history",{headers:auth});
 expect(r.status()).toBe(200);
 const rows=await r.json() as {id:string;mode:string}[];
 const id=rows.find(x=>x.mode===mode)?.id;
 expect(id).toBeTruthy();
 const state=await request.get(API+"/v11/api-vapt/assessments/"+id,{headers:auth});
 expect(state.status()).toBe(200);
 const v=await state.json() as {id:string;status:string;children:{engine_version:string;status:string}[]};
 expect(v.id).toBe(id);
 expect(v.status).toBe("QUEUED");
 expect(v.children.length).toBe(mode==="OFFLINE_ONLY"?1:2);
 expect(v.children.every(x=>x.status==="QUEUED")).toBe(true);
 return id!;
}
async function actualProgress(request:APIRequestContext,id:string,expected:{parent:string;offline:string;pt?:string}){
 const r=await request.get(API+"/v11/api-vapt/assessments/"+id,{headers:auth});
 expect(r.status(),await r.text()).toBe(200);
 const v=await r.json() as {status:string;children:{engine_version:string;status:string}[]};
 expect(v.status).toBe(expected.parent);
 const offline=v.children.find(x=>x.engine_version.startsWith("inventory-"));
 expect(offline?.status).toBe(expected.offline);
 if(expected.pt){
  expect(v.children.find(x=>x.engine_version==="pt-orchestrator-v1")?.status).toBe(expected.pt);
 }
}
test("Phase11 Chromium: one-click real offline→governed PT→unified findings/report/JSON, no customer network",async({page,request})=>{
 test.setTimeout(150000);
 const outside:string[]=[];page.on("request",r=>{if(r.url().includes(".fixture.invalid"))outside.push(r.url());});
 const {tid,scopeId}=await seed(request);
 const panel=await open(page,tid);
 await panel.getByLabel("Authorized synthetic scope").selectOption(scopeId);
 await expect(panel.getByText("Planned evaluations: 14",{exact:false})).toBeVisible({timeout:20000});
 await expect(panel.getByText("Permit readiness: VALID",{exact:false})).toBeVisible();
 await panel.getByRole("button",{name:"Start one autonomous assessment"}).click();
 const id=await admitted(request,tid,"GOVERNED_SYNTHETIC");
 await expect(panel.getByText("Parent: QUEUED",{exact:false})).toBeVisible({timeout:20000});
 expect(await processOneJob()).toBe(true);
 await actualProgress(request,id,{parent:"QUEUED",offline:"COMPLETED",pt:"QUEUED"});
 await expect(panel.getByText("inventory-v2: COMPLETED",{exact:false})).toBeVisible({timeout:20000});
 expect(await processOneJob()).toBe(true);
 await actualProgress(request,id,{parent:"QUEUED",offline:"COMPLETED",pt:"COMPLETED"});
 expect(await processOneJob()).toBe(true);
 await actualProgress(request,id,{parent:"COMPLETED",offline:"COMPLETED",pt:"COMPLETED"});
 await expect(panel.getByText("Immutable composite security report")).toBeVisible({timeout:20000});
 await expect(panel.getByText("PT rules 8/8",{exact:false})).toBeVisible();
 await expect(panel.getByText("evaluations 14/14",{exact:false})).toBeVisible();
 const report=await request.get(API+"/v11/api-vapt/assessments/"+id+"/report",{headers:auth});
 expect(report.status(),await report.text()).toBe(200);
 const value=await report.json() as {fullAuthorizedVaptCompleted:boolean;verifiedFixed:boolean;customerRuntimeVerified:boolean;components:{status:string}[]};
 expect(value.fullAuthorizedVaptCompleted).toBe(true);expect(value.verifiedFixed).toBe(false);
 expect(value.customerRuntimeVerified).toBe(false);
 expect(value.components.every(c=>c.status==="COMPLETED")).toBe(true);
 expect((await request.get(API+"/v11/api-vapt/assessments/"+id+"/export",{headers:auth})).status()).toBe(200);
 expect((await request.get(API+"/v11/api-vapt/assessments/"+id+"/report",{headers:other})).status()).toBe(409);
 expect(outside).toEqual([]);
});
test("Phase11 Chromium: offline-only genuinely executes without permit, no authorized PT success",async({page,request})=>{
 test.setTimeout(150000);
 const {tid,sid}=await seed(request,false);
 const panel=await open(page,tid);
 await panel.getByLabel("Assessment mode").selectOption("OFFLINE_ONLY");
 await panel.getByLabel("Immutable specification").selectOption(sid);
 await panel.getByRole("button",{name:"Start one autonomous assessment"}).click();
 const id=await admitted(request,tid,"OFFLINE_ONLY");
 await expect(panel.getByText("Parent: QUEUED",{exact:false})).toBeVisible({timeout:20000});
 expect(await processOneJob()).toBe(true);
 await actualProgress(request,id,{parent:"QUEUED",offline:"COMPLETED"});
 expect(await processOneJob()).toBe(true);
 await actualProgress(request,id,{parent:"COMPLETED",offline:"COMPLETED"});
 await expect(panel.getByText("Immutable composite security report")).toBeVisible({timeout:20000});
 await expect(panel.getByText("OFFLINE_ONLY — runtime testing NOT performed")).toBeVisible();
 const report=await request.get(API+"/v11/api-vapt/assessments/"+id+"/report",{headers:auth});
 expect(report.status()).toBe(200);
 expect((await report.json() as {coverage:{ptEvaluationsExecuted:number}}).coverage.ptEvaluationsExecuted).toBe(0);
});
test("Phase11 Chromium: missing synthetic permit prevents admission before runtime",async({page,request})=>{
 test.setTimeout(150000);
 const {tid,scopeId}=await seed(request,false);
 const panel=await open(page,tid);
 await panel.getByLabel("Authorized synthetic scope").selectOption(scopeId);
 await expect(panel.getByText("AUTHORIZATION_MISSING",{exact:false})).toBeVisible();
 await expect(panel.getByRole("button",{name:"Start one autonomous assessment"})).toBeDisabled();
 const denied=await request.post(API+"/v11/api-vapt/assessments",{
  headers:{...auth,"idempotency-key":"pt11-unsigned-"+randomUUID()},
  data:{mode:"GOVERNED_SYNTHETIC",scopeId,policyId:"SYNTHETIC_PT_COMPLETE_SUPPORTED",profile:"SECURE_BASELINE"}});
 expect(denied.status()).toBe(409);
 const history=await request.get(API+"/v11/api-vapt/targets/"+tid+"/history",{headers:auth});
 expect(await history.json()).toEqual([]);
});

test("Phase11 Chromium: cancellation after completed offline analysis prevents a successful parent report",async({page,request})=>{
 test.setTimeout(150000);
 const {tid,scopeId}=await seed(request);
 const panel=await open(page,tid);
 await panel.getByLabel("Authorized synthetic scope").selectOption(scopeId);
 await expect(panel.getByText("Permit readiness: VALID",{exact:false})).toBeVisible();
 await panel.getByRole("button",{name:"Start one autonomous assessment"}).click();
 // Wait for persisted server admission before reading history; click starts an asynchronous request.
 await expect(panel.getByText("Persisted execution progress")).toBeVisible({timeout:20000});
 await expect.poll(async()=>{
  const response=await request.get(API+"/v11/api-vapt/targets/"+tid+"/history",{headers:auth});
  expect(response.status()).toBe(200);
  return (await response.json() as {id:string}[]).length;
 },{timeout:20000}).toBeGreaterThan(0);
 const history=await request.get(API+"/v11/api-vapt/targets/"+tid+"/history",{headers:auth});
 const id=(await history.json() as {id:string}[])[0]!.id;
 expect(await processOneJob()).toBe(true);
 await panel.getByRole("button",{name:"Cancel assessment"}).click();
 await expect(panel.getByText("Terminal diagnostics (not successful VAPT)")).toBeVisible({timeout:15000});
 expect((await request.get(API+"/v11/api-vapt/assessments/"+id+"/report",{headers:auth})).status()).toBe(409);
 const state=await request.get(API+"/v11/api-vapt/assessments/"+id,{headers:auth});
 expect((await state.json() as {status:string}).status).toBe("CANCELLED");
});
test("Phase11 Chromium: controlled reassessment creates fresh identity without rewriting historical report",async({request})=>{
 test.setTimeout(150000);
 const {scopeId}=await seed(request);
 const requestData={mode:"GOVERNED_SYNTHETIC",scopeId,
  policyId:"SYNTHETIC_PT_AUTHORIZATION_FOCUSED",profile:"SECURE_BASELINE"};
 const first=await request.post(API+"/v11/api-vapt/assessments",{
  headers:{...auth,"idempotency-key":"pt11-first-"+randomUUID()},data:requestData});
 expect(first.status(),await first.text()).toBe(201);
 const oldId=(await first.json() as {id:string}).id;
 for(let i=0;i<3;i++)expect(await processOneJob()).toBe(true);
 const oldReport=await request.get(API+"/v11/api-vapt/assessments/"+oldId+"/report",{headers:auth});
 expect(oldReport.status()).toBe(200);
 const historical=await oldReport.text();
 const next=await request.post(API+"/v11/api-vapt/assessments/"+oldId+"/reassess",{
  headers:{...auth,"idempotency-key":"pt11-fresh-"+randomUUID()},data:{}});
 expect(next.status(),await next.text()).toBe(201);
 const newId=(await next.json() as {id:string}).id;expect(newId).not.toBe(oldId);
 for(let i=0;i<3;i++)expect(await processOneJob()).toBe(true);
 const current=await request.get(API+"/v11/api-vapt/assessments/"+newId+"/report",{headers:auth});
 expect(current.status(),await current.text()).toBe(200);
 const oldAgain=await request.get(API+"/v11/api-vapt/assessments/"+oldId+"/report",{headers:auth});
 expect(await oldAgain.text()).toBe(historical);
 const compared=await request.get(API+"/v11/api-vapt/assessments/"+oldId+"/compare/"+newId,{headers:auth});
 expect(compared.status(),await compared.text()).toBe(200);
 const diff=await compared.json() as {compatibility:string;verifiedFixed:boolean};
 expect(diff.compatibility).toBe("COMPATIBLE");expect(diff.verifiedFixed).toBe(false);
});

test("Phase11 Chromium: governed vulnerable fixture produces actual SYNTHETIC_PT observations without customer confirmation",async({request})=>{
 test.setTimeout(150000);
 const {scopeId}=await seed(request);
 const run=await request.post(API+"/v11/api-vapt/assessments",{
  headers:{...auth,"idempotency-key":"pt11-observed-"+randomUUID()},
  data:{mode:"GOVERNED_SYNTHETIC",scopeId,policyId:"SYNTHETIC_PT_COMPLETE_SUPPORTED",
   profile:"MISSING_AUTH_ENFORCEMENT"}});
 expect(run.status(),await run.text()).toBe(201);
 const id=(await run.json() as {id:string}).id;
 for(let i=0;i<3;i++)expect(await processOneJob()).toBe(true);
 const response=await request.get(API+"/v11/api-vapt/assessments/"+id+"/report",{headers:auth});
 expect(response.status(),await response.text()).toBe(200);
 const report=await response.json() as {verifiedFixed:boolean;customerRuntimeVerified:boolean;
  confirmedCustomerVulnerabilities:unknown[];
  findings:{source:string;verifiedFixed:boolean;customerVulnerabilityConfirmed:boolean}[];
  pt:{syntheticObservations:number}};
 expect(report.pt.syntheticObservations).toBeGreaterThan(0);
 expect(report.findings.some(x=>x.source==="SYNTHETIC_PT")).toBe(true);
 expect(report.findings.every(x=>x.verifiedFixed===false&&x.customerVulnerabilityConfirmed===false)).toBe(true);
 expect(report.verifiedFixed).toBe(false);
 expect(report.customerRuntimeVerified).toBe(false);
 expect(report.confirmedCustomerVulnerabilities).toEqual([]);
});

test("Phase11 Chromium: consumed permit requires newly signed same-target scope for safe UI reassessment",async({page,request})=>{
 test.setTimeout(150000);
 const {tid,sid,scopeId}=await seed(request);
 const prior=await request.post(API+"/v11/api-vapt/assessments",{
  headers:{...auth,"idempotency-key":"pt11-consumed-"+randomUUID()},
  data:{mode:"GOVERNED_SYNTHETIC",scopeId,
   policyId:"SYNTHETIC_PT_COMPLETE_SUPPORTED",profile:"SECURE_BASELINE"}});
 expect(prior.status(),await prior.text()).toBe(201);
 const oldId=(await prior.json() as {id:string}).id;
 for(let i=0;i<3;i++)expect(await processOneJob()).toBe(true);
 const historyBefore=await request.get(API+"/v11/api-vapt/assessments/"+oldId+"/report",{headers:auth});
 expect(historyBefore.status()).toBe(200);
 const ops=await request.get(API+"/v2/specifications/"+sid+"/operations?limit=100",{headers:auth});
 expect(ops.status()).toBe(200);
 const keys=(await ops.json() as {key:string;method:string;path:string}[])
  .filter(x=>x.method==="GET"&&["/pt/account","/pt/resources/bob","/pt/admin","/pt/confidential"].includes(x.path))
  .map(x=>x.key);
 const fresh=await request.post(API+"/v6/pt/targets/"+tid+"/scopes",{
  headers:{...auth,"idempotency-key":"pt11-new-scope-"+randomUUID()},
  data:{specificationId:sid,operationKeys:keys,fixtureId:"pt-security-v1",
   exclusions:[],maxEvaluations:14,ratePerMinute:14,maxConcurrency:1,deadlineMs:30000,validityMinutes:15}});
 expect(fresh.status(),await fresh.text()).toBe(201);
 const newScopeId=(await fresh.json() as {id:string}).id;
 expect((await request.post(API+"/v6/pt/scopes/"+newScopeId+"/request-authorization",
  {headers:auth,data:{}})).status()).toBe(201);
 expect((await request.post(API+"/v6/pt/test-authority/scopes/"+newScopeId+"/issue",
  {headers:issuer,data:{}})).status()).toBe(201);
 const panel=await open(page,tid);
 await expect(panel.getByRole("button",{name:/GOVERNED_SYNTHETIC · COMPLETED/}).first()).toBeVisible();
 await panel.getByRole("button",{name:/GOVERNED_SYNTHETIC · COMPLETED/}).first().click();
 await expect(panel.getByText("Immutable composite security report")).toBeVisible({timeout:20000});
 await panel.getByLabel("Authorized synthetic scope").selectOption(newScopeId);
 const reassessmentResponse=page.waitForResponse(r=>
  r.url().includes("/v11/api-vapt/assessments/")&&r.url().endsWith("/reassess")&&
  r.request().method()==="POST");
 await panel.getByRole("button",{name:"Reassess using selected signed scope"}).click();
 expect((await reassessmentResponse).status()).toBe(201);
 const targetHistory=await request.get(API+"/v11/api-vapt/targets/"+tid+"/history",{headers:auth});
 expect(targetHistory.status()).toBe(200);
 const list=await targetHistory.json() as {id:string}[];
 const newId=list.find(x=>x.id!==oldId)?.id;
 expect(newId).toBeTruthy();
 for(let i=0;i<3;i++)expect(await processOneJob()).toBe(true);
 await expect(panel.getByText("Immutable composite security report")).toBeVisible({timeout:30000});
 const compare=await request.get(API+"/v11/api-vapt/assessments/"+oldId+"/compare/"+newId,{headers:auth});
 expect(compare.status()).toBe(200);
 expect((await compare.json() as {compatibility:string}).compatibility).toBe("INCOMPATIBLE");
 expect((await request.get(API+"/v11/api-vapt/assessments/"+oldId+"/report",{headers:auth})).status()).toBe(200);
});
