/** Phase14 F5 real React → Fastify → PostgreSQL negative concurrency and cancellation.
 * Route barriers delay genuine requests; no fabricated success response is used.
 */
import {test,expect,type APIRequestContext,type Page} from "@playwright/test";
import {randomUUID} from "node:crypto";
import {readFileSync} from "node:fs";
import {performance} from "node:perf_hooks";
import {withTenant,closeDatabase} from "../../packages/database/src/index.js";
import {processOneJob} from "../../packages/worker/src/index.js";
const API="http://127.0.0.1:3001";
const A="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const auth={authorization:"Bearer local-test-token-alpha"};
const other={authorization:"Bearer local-test-token-beta"};
const fixture=readFileSync(new URL("../../fixtures/phase07-security.openapi.json",import.meta.url),"utf8");
type RecordRow={id:string;status:string;mode:string};
function barrier(){
 let unlock!:()=>void,notify!:()=>void;
 const promise=new Promise<void>(resolve=>{unlock=resolve;});
 const entered=new Promise<void>(resolve=>{notify=resolve;});
 return {promise,unlock,notify,entered};
}
async function seed(request:APIRequestContext){
 const suffix=randomUUID().slice(0,10);
 const t=await request.post(API+"/v1/targets",{headers:auth,
  data:{name:"Phase14 F5 "+suffix,environment:"SYNTHETIC",
   baseUrl:"https://f5-"+suffix+".fixture.invalid"}});
 expect(t.status(),await t.text()).toBe(201);
 const target=(await t.json() as {id:string}).id;
 const spec=await request.post(API+"/v2/targets/"+target+"/specifications/imports",{
  headers:{...auth,"idempotency-key":"f5-import-"+randomUUID()},
  data:{filename:"phase07-security.openapi.json",content:fixture}});
 expect(spec.status(),await spec.text()).toBe(201);
 return {target,spec:(await spec.json() as {specificationId:string}).specificationId};
}
async function history(request:APIRequestContext,target:string,headers=auth):Promise<RecordRow[]>{
 const r=await request.get(API+"/v11/api-vapt/targets/"+target+"/history?limit=30",{headers});
 expect(r.status(),await r.text()).toBe(200);
 return await r.json() as RecordRow[];
}
async function setupPage(page:Page,target:string,spec:string){
 await page.goto("/");
 await page.getByLabel("Select target").selectOption(target);
 const panel=page.getByRole("region",{name:"Autonomous API VAPT workspace"});
 await expect(panel).toBeVisible();
 await panel.getByLabel("Assessment mode").selectOption("OFFLINE_ONLY");
 await panel.getByLabel("Immutable specification").selectOption(spec);
 await expect(panel.getByRole("button",{name:"Start one autonomous assessment"})).toBeEnabled();
 return panel;
}
test.afterAll(async()=>{await closeDatabase();});

test("F5 real browser: pending admission blocks repeated click, identical key commits once",async({page,request})=>{
 test.setTimeout(90000);
 const {target,spec}=await seed(request);
 const panel=await setupPage(page,target,spec);
 const gate=barrier();let submits=0,key="";
 await page.route("**/v11/api-vapt/assessments",async route=>{
  if(route.request().method()!=="POST"){await route.continue();return;}
  submits++;key=route.request().headers()["idempotency-key"]??"";
  gate.notify();await gate.promise;await route.continue();
 });
 const start=panel.getByRole("button",{name:"Start one autonomous assessment"});
 await start.click();await gate.entered;
 await expect(start).toBeDisabled();
 await start.evaluate((el:HTMLButtonElement)=>el.click());
 expect(submits).toBe(1);
 expect(await history(request,target)).toHaveLength(0);
 gate.unlock();
 await expect.poll(async()=>(await history(request,target)).length).toBe(1);
 await expect(start).toBeEnabled();
 const first=(await history(request,target))[0]!;
 expect(first.status).toBe("QUEUED");
 const replay=await request.post(API+"/v11/api-vapt/assessments",{
  headers:{...auth,"idempotency-key":key},
  data:{mode:"OFFLINE_ONLY",targetId:target,specificationId:spec}});
 expect(replay.status(),await replay.text()).toBe(200);
 expect((await replay.json() as {id:string}).id).toBe(first.id);
 const sql=await withTenant(A,tx=>tx.query(
  "SELECT count(*)::int AS n FROM api_vapt11_assessments WHERE target_id=$1",[target]));
 expect(sql.rows[0].n).toBe(1);
 expect((await request.get(API+"/v11/api-vapt/assessments/"+first.id+"/report",{headers:auth})).status()).toBe(409);
 await expect(panel.getByRole("status")).toContainText("QUEUED");
});

test("F5 concurrent distinct-key submissions persist separately; cancellation before claim is terminal",async({request})=>{
 const {target,spec}=await seed(request);
 const payload={mode:"OFFLINE_ONLY",targetId:target,specificationId:spec};
 const [a,b]=await Promise.all([request.post(API+"/v11/api-vapt/assessments",{
  headers:{...auth,"idempotency-key":"f5-a-"+randomUUID()},data:payload}),
  request.post(API+"/v11/api-vapt/assessments",{
   headers:{...auth,"idempotency-key":"f5-b-"+randomUUID()},data:payload})]);
 expect(a.status(),await a.text()).toBe(201);expect(b.status(),await b.text()).toBe(201);
 const ids=[(await a.json() as {id:string}).id,(await b.json() as {id:string}).id];
 expect(new Set(ids).size).toBe(2);
 expect((await history(request,target)).map(v=>v.id).sort()).toEqual([...ids].sort());
 for(const id of ids){
  const cancel=await request.post(API+"/v11/api-vapt/assessments/"+id+"/cancel",{headers:auth,data:{}});
  expect(cancel.status(),await cancel.text()).toBe(200);
  const state=await request.get(API+"/v11/api-vapt/assessments/"+id,{headers:auth});
  expect((await state.json() as {status:string}).status).toBe("CANCELLED");
  expect((await request.get(API+"/v11/api-vapt/assessments/"+id+"/report",{headers:auth})).status()).toBe(409);
 }
 const sql=await withTenant(A,tx=>tx.query(
  "SELECT count(*)::int AS n FROM api_vapt11_reports WHERE parent_assessment_id=ANY($1::uuid[])",[ids]));
 expect(sql.rows[0].n).toBe(0);
});

test("F5 UI cancellation after admission remains durable; wrong tenant has no report",async({page,request})=>{
 const {target,spec}=await seed(request);
 const panel=await setupPage(page,target,spec);
 await panel.getByRole("button",{name:"Start one autonomous assessment"}).click();
 await expect(panel.getByRole("button",{name:"Cancel assessment"})).toBeVisible();
 const rows=await history(request,target);expect(rows).toHaveLength(1);
 const id=rows[0]!.id;
 await panel.getByRole("button",{name:"Cancel assessment"}).click();
 await expect(panel.getByText("Terminal diagnostics (not successful VAPT)")).toBeVisible();
 await expect(panel.getByRole("status")).toContainText("CANCELLED");
 const state=await request.get(API+"/v11/api-vapt/assessments/"+id,{headers:auth});
 expect((await state.json() as {status:string}).status).toBe("CANCELLED");
 expect((await request.get(API+"/v11/api-vapt/assessments/"+id+"/report",{headers:auth})).status()).toBe(409);
 expect((await request.get(API+"/v11/api-vapt/assessments/"+id,{headers:other})).status()).toBe(404);
 expect((await withTenant(A,tx=>tx.query(
  "SELECT count(*)::int AS n FROM api_vapt11_reports WHERE parent_assessment_id=$1",[id]))).rows[0].n).toBe(0);
});

test("F5 late authentic queued browser response cannot roll back UI cancellation",async({page,request})=>{
 test.setTimeout(90000);
 const {target,spec}=await seed(request);
 const panel=await setupPage(page,target,spec);
 await panel.getByRole("button",{name:"Start one autonomous assessment"}).click();
 await expect(panel.getByRole("button",{name:"Cancel assessment"})).toBeVisible();
 const id=(await history(request,target))[0]!.id;
 const gate=barrier();let captured=false;
 await page.route("**/v11/api-vapt/assessments/"+id,async route=>{
  if(captured){await route.continue();return;}
  captured=true;const response=await route.fetch();
  expect((await response.json() as {status:string}).status).toBe("QUEUED");
  gate.notify();await gate.promise;
  await route.fulfill({response}); // actual pre-cancellation Fastify response, NOT mocked success
 });
 // Existing UI polls every 1500ms. The barrier synchronizes with a real response.
 await gate.entered;
 await panel.getByRole("button",{name:"Cancel assessment"}).click();
 await expect(panel.getByRole("status")).toContainText("CANCELLED");
 gate.unlock();
 await expect(panel.getByRole("status")).toContainText("CANCELLED");
 await expect(panel.getByText("Terminal diagnostics (not successful VAPT)")).toBeVisible();
 const s=await request.get(API+"/v11/api-vapt/assessments/"+id,{headers:auth});
 expect((await s.json() as {status:string}).status).toBe("CANCELLED");
 expect((await request.get(API+"/v11/api-vapt/assessments/"+id+"/report",{headers:auth})).status()).toBe(409);
});

test("F5 transport rejection restores focus and retry commits only genuine parent",async({page,request})=>{
 const {target,spec}=await seed(request);
 const panel=await setupPage(page,target,spec);
 let denied=0;
 await page.route("**/v11/api-vapt/assessments",async route=>{
  if(route.request().method()==="POST"&&denied++===0){
   await route.fulfill({status:503,contentType:"application/json",
    body:JSON.stringify({error:"SYNTHETIC_UNAVAILABLE"})});return;
  }
  await route.continue();
 });
 const start=panel.getByRole("button",{name:"Start one autonomous assessment"});
 await start.click();
 await expect(panel.getByRole("alert")).toContainText("SYNTHETIC_UNAVAILABLE");
 await expect(start).toBeFocused();await expect(start).toBeEnabled();
 expect(await history(request,target)).toHaveLength(0);
 await page.unroute("**/v11/api-vapt/assessments");
 await start.press("Enter");
 await expect.poll(async()=>(await history(request,target)).length).toBe(1);
 await expect(panel.getByRole("alert")).toHaveCount(0);
 expect((await history(request,target))[0]!.status).toBe("QUEUED");
});

test("F5 token change while admission withheld cannot display other tenant state",async({page,request})=>{
 test.setTimeout(90000);
 const {target,spec}=await seed(request);
 const panel=await setupPage(page,target,spec);
 const gate=barrier();
 await page.route("**/v11/api-vapt/assessments",async route=>{
  if(route.request().method()!=="POST"){await route.continue();return;}
  gate.notify();await gate.promise;await route.continue();
 });
 await panel.getByRole("button",{name:"Start one autonomous assessment"}).click();
 await gate.entered;
 await page.getByLabel("Synthetic development token (never a production login)").fill("local-test-token-beta");
 await expect(page.getByRole("region",{name:"Autonomous API VAPT workspace"})).toHaveCount(0);
 gate.unlock();
 await expect.poll(async()=>(await history(request,target)).length).toBe(1);
 expect(await history(request,target,other)).toEqual([]);
 expect(await page.getByRole("region",{name:"Autonomous API VAPT workspace"}).count()).toBe(0);
 expect(await page.getByText("Immutable composite security report").count()).toBe(0);
});

test("F5 partial execution then cancel rejects false successful parent and immutable report",async({page,request})=>{
 test.setTimeout(90000);
 const {target,spec}=await seed(request);
 const panel=await setupPage(page,target,spec);
 await panel.getByRole("button",{name:"Start one autonomous assessment"}).click();
 const id=(await history(request,target))[0]!.id;
 // The shared real queue contains other previous synthetic fixtures. Do not
 // confuse an unrelated successful worker claim with this parent's child.
 let partial:{status:string;children:{status:string}[]}|null=null;
 for(let i=0;i<30;i++){
  const mid=await request.get(API+"/v11/api-vapt/assessments/"+id,{headers:auth});
  expect(mid.status()).toBe(200);
  partial=await mid.json() as {status:string;children:{status:string}[]};
  if(partial.children.some(c=>c.status==="COMPLETED"))break;
  expect(await processOneJob(),"real PostgreSQL queue must progress").toBe(true);
 }
 expect(partial?.status).toBe("QUEUED");
 expect(partial?.children.some(c=>c.status==="COMPLETED")).toBe(true);
 await panel.getByRole("button",{name:"Cancel assessment"}).click();
 await expect(panel.getByRole("status")).toContainText("CANCELLED");
 expect((await request.get(API+"/v11/api-vapt/assessments/"+id+"/report",{headers:auth})).status()).toBe(409);
 expect((await withTenant(A,tx=>tx.query(
  "SELECT count(*)::int AS n FROM api_vapt11_reports WHERE parent_assessment_id=$1",[id]))).rows[0].n).toBe(0);
});

test("F5 cancellation before durable admission aborts browser transport without false PostgreSQL admission",async({page,request})=>{
 test.setTimeout(90000);
 const {target,spec}=await seed(request),panel=await setupPage(page,target,spec);
 const gate=barrier();let intercepts=0;
 await page.route("**/v11/api-vapt/assessments",async route=>{
  if(route.request().method()!=="POST"){await route.continue();return;}
  intercepts++;gate.notify();await gate.promise;
  await route.abort("failed");
 });
 const button=panel.getByRole("button",{name:"Start one autonomous assessment"});
 await button.click();await gate.entered;
 await expect(button).toBeDisabled();
 expect(await history(request,target)).toHaveLength(0);
 gate.unlock();await expect(panel.getByRole("alert")).toBeVisible();
 await expect(button).toBeFocused();await expect(button).toBeEnabled();
 expect(intercepts).toBe(1);expect(await history(request,target)).toHaveLength(0);
 expect((await withTenant(A,tx=>tx.query(
  "SELECT count(*)::int AS n FROM api_vapt11_assessments WHERE target_id=$1",[target]))).rows[0].n).toBe(0);
 await page.unroute("**/v11/api-vapt/assessments");
 await button.press("Enter");
 await expect.poll(async()=>(await history(request,target)).length).toBe(1);
});

test("F5 navigation away before admission forwarding leaves no parent or cross-tenant state",async({page,request})=>{
 test.setTimeout(90000);
 const {target,spec}=await seed(request),panel=await setupPage(page,target,spec);
 const gate=barrier();
 await page.route("**/v11/api-vapt/assessments",async route=>{
  if(route.request().method()!=="POST"){await route.continue();return;}
  gate.notify();await gate.promise;
  // Browser navigation cancelled the original document; this is a transport
  // abort only, never an invented committed HTTP response.
  try{await route.abort("aborted");}catch{ /* original network was already disposed */ }
 });
 await panel.getByRole("button",{name:"Start one autonomous assessment"}).click();
 await gate.entered;expect(await history(request,target)).toHaveLength(0);
 await page.goto("about:blank");
 gate.unlock();
 expect(await history(request,target)).toHaveLength(0);
 await page.goto("/");
 await page.getByLabel("Synthetic development token (never a production login)").fill("local-test-token-beta");
 expect(await page.getByRole("region",{name:"Autonomous API VAPT workspace"}).count()).toBe(0);
 expect((await withTenant(A,tx=>tx.query(
  "SELECT count(*)::int AS n FROM api_vapt11_assessments WHERE target_id=$1",[target]))).rows[0].n).toBe(0);
});

test("F5 HTTP 429 admission denial at 320px and 200% text with accessible alert and keyboard recovery",async({page,request})=>{
 const {target,spec}=await seed(request);
 await page.setViewportSize({width:320,height:760});
 await page.emulateMedia({reducedMotion:"reduce"});
 await page.goto("/");
 await page.getByLabel("Select target").selectOption(target);
 const panel=page.getByRole("region",{name:"Autonomous API VAPT workspace"});
 await panel.getByLabel("Assessment mode").selectOption("OFFLINE_ONLY");
 await panel.getByLabel("Immutable specification").selectOption(spec);
 await page.evaluate(()=>{
  document.documentElement.style.fontSize="200%";
  document.documentElement.dir="rtl"; // test-only direction stress; not a translation or locale claim
 });
 await expect(page.locator("html")).toHaveAttribute("dir","rtl");
 let denies=0;
 await page.route("**/v11/api-vapt/assessments",async route=>{
  if(route.request().method()==="POST"&&denies++===0){
   await route.fulfill({status:429,contentType:"application/json",
    body:JSON.stringify({error:"QUEUE_TENANT_CAPACITY_EXCEEDED"})});return;
  }
  await route.continue();
 });
 const start=panel.getByRole("button",{name:"Start one autonomous assessment"});
 await start.click();
 await expect(panel.getByRole("alert")).toContainText("QUEUE_TENANT_CAPACITY_EXCEEDED");
 await expect(start).toBeFocused();await expect(start).toBeEnabled();
 expect(await history(request,target)).toHaveLength(0);
 expect(await page.evaluate(()=>matchMedia("(prefers-reduced-motion: reduce)").matches)).toBe(true);
 await page.unroute("**/v11/api-vapt/assessments");
 await start.press("Enter");
 await expect.poll(async()=>(await history(request,target)).length).toBe(1);
 await expect(panel.getByRole("alert")).toHaveCount(0);
 expect((await history(request,target))[0]!.status).toBe("QUEUED");
});

test("F5 failed cancellation cannot create false terminal status; on retry retains immutable authority",async({page,request})=>{
 const {target,spec}=await seed(request),panel=await setupPage(page,target,spec);
 await panel.getByRole("button",{name:"Start one autonomous assessment"}).click();
 const id=(await history(request,target))[0]!.id;
 const cancel=panel.getByRole("button",{name:"Cancel assessment"});
 await expect(cancel).toBeEnabled();
 let denies=0;
 await page.route("**/v11/api-vapt/assessments/"+id+"/cancel",async route=>{
  if(denies++===0){await route.fulfill({status:503,contentType:"application/json",
   body:JSON.stringify({error:"CANCEL_TEMPORARILY_UNAVAILABLE"})});return;}
  await route.continue();
 });
 await cancel.click();await expect(panel.getByRole("alert")).toContainText("CANCEL_TEMPORARILY_UNAVAILABLE");
 await expect(cancel).toBeFocused();await expect(cancel).toBeEnabled();
 expect((await history(request,target))[0]!.status).toBe("QUEUED");
 await page.unroute("**/v11/api-vapt/assessments/"+id+"/cancel");
 await cancel.press("Enter");
 await expect(panel.getByRole("status")).toContainText("CANCELLED");
 expect((await history(request,target))[0]!.status).toBe("CANCELLED");
 expect((await request.get(API+"/v11/api-vapt/assessments/"+id+"/report",{headers:auth})).status()).toBe(409);
 expect((await withTenant(A,tx=>tx.query(
  "SELECT count(*)::int AS n FROM api_vapt11_reports WHERE parent_assessment_id=$1",[id]))).rows[0].n).toBe(0);
});

test("F5 governed scope revocation is visible, admission denied and no browser-triggered PT executes",async({page,request})=>{
 test.setTimeout(90000);
 const {target,spec}=await seed(request);
 const operations=await request.get(API+"/v2/specifications/"+spec+"/operations?limit=100",{headers:auth});
 expect(operations.status(),await operations.text()).toBe(200);
 const ops=await operations.json() as {path:string;method:string;key:string}[];
 const keys=["/pt/account","/pt/resources/bob","/pt/admin","/pt/confidential"]
  .map(path=>ops.find(x=>x.method==="GET"&&x.path===path)?.key);
 expect(keys.every(Boolean)).toBe(true);
 const scope=await request.post(API+"/v6/pt/targets/"+target+"/scopes",{
  headers:{...auth,"idempotency-key":"f5-scope-"+randomUUID()},
  data:{specificationId:spec,operationKeys:keys,fixtureId:"pt-security-v1",exclusions:[],
   maxEvaluations:14,ratePerMinute:14,maxConcurrency:1,deadlineMs:30000,validityMinutes:15}});
 expect(scope.status(),await scope.text()).toBe(201);
 const sid=(await scope.json() as {id:string}).id;
 const authRequest=await request.post(API+"/v6/pt/scopes/"+sid+"/request-authorization",{headers:auth,data:{}});
 expect(authRequest.status(),await authRequest.text()).toBe(201);
 const authority={...auth,"x-pt-authority-key":process.env.PT_TEST_AUTHORITY_KEY??""};
 const issued=await request.post(API+"/v6/pt/test-authority/scopes/"+sid+"/issue",{headers:authority,data:{}});
 expect(issued.status(),await issued.text()).toBe(201);
 const permit=(await issued.json() as {id:string}).id;
 await page.goto("/");
 await page.getByLabel("Select target").selectOption(target);
 const panel=page.getByRole("region",{name:"Autonomous API VAPT workspace"});
 await expect(panel.getByText("Permit readiness:")).toContainText("VALID");
 const start=panel.getByRole("button",{name:"Start one autonomous assessment"});
 await expect(start).toBeEnabled();
 const revoke=await request.post(API+"/v6/pt/test-authority/permits/"+permit+"/revoke",{
  headers:authority,data:{}});
 expect(revoke.status(),await revoke.text()).toBe(200);
 // A stale browser preview never confers server execution authority.
 await start.click();
 await expect(panel.getByRole("alert")).toBeVisible();
 expect(await history(request,target)).toHaveLength(0);
 await panel.getByLabel("Trusted fixture profile").selectOption("MISSING_AUTH_ENFORCEMENT");
 await expect(panel.getByText("Permit readiness:")).toContainText("BLOCKED");
 await expect(start).toBeDisabled();
 expect(await history(request,target)).toHaveLength(0);
 const receipt=await withTenant(A,tx=>tx.query(
  "SELECT count(*)::int AS n FROM api_pt_detection_evaluations WHERE assessment_id IN (SELECT id FROM api_assessments WHERE target_id=$1)",[target]));
 expect(receipt.rows[0].n).toBe(0);
});

test("F5 E7 actual Chromium operation admission/cancellation transition distributions without fake server success",async({page,request})=>{
 test.setTimeout(120000);
 const {target,spec}=await seed(request);
 const panel=await setupPage(page,target,spec);
 const samples:{admit:number;cancel:number}[]=[],warmup=2,iterations=10;
 const cpu=process.cpuUsage(),heap=process.memoryUsage().heapUsed;
 const start=panel.getByRole("button",{name:"Start one autonomous assessment"});
 for(let i=0;i<iterations;i++){
  const t0=performance.now();
  await start.click();
  await expect.poll(async()=>(await history(request,target)).length).toBe(i+1);
  await expect(panel.getByRole("button",{name:"Cancel assessment"})).toBeVisible();
  await expect(panel.getByRole("status")).toContainText("QUEUED");
  const admitted=performance.now()-t0;
  const t1=performance.now();
  await panel.getByRole("button",{name:"Cancel assessment"}).click();
  await expect(panel.getByRole("status")).toContainText("CANCELLED");
  const cancelled=performance.now()-t1;
  const rows=await history(request,target);
  expect(rows).toHaveLength(i+1);
  expect(rows.every(x=>x.status==="CANCELLED")).toBe(true);
  const latest=rows.find(x=>x.status==="CANCELLED"&&x.id!==undefined);
  expect(latest).toBeDefined();
  if(i>=warmup)samples.push({admit:admitted,cancel:cancelled});
 }
 function calc(key:"admit"|"cancel"){
  const values=samples.map(x=>x[key]).sort((a,b)=>a-b);
  expect(values).toHaveLength(8);expect(values.every(x=>Number.isFinite(x)&&x>=0)).toBe(true);
  return {medianMs:Number(values[3]!.toFixed(3)),
   p95Ms:Number(values[Math.ceil(values.length*.95)-1]!.toFixed(3)),samples:8};
 }
 const cpuUsed=process.cpuUsage(cpu);
 console.log("PHASE14_E7_REAL_BROWSER_TRANSITIONS "+JSON.stringify({
  admission:calc("admit"),cancellation:calc("cancel"),warmup,iterations,concurrency:1,
  fixture:"10 committed offline synthetic parents with real cancellation and no reports",
  cpuUserMicros:cpuUsed.user,cpuSystemMicros:cpuUsed.system,
  heapDeltaBytes:process.memoryUsage().heapUsed-heap,
  noProductionSlo:true,customerNetworkRequests:0,errors:0,
  runner:"GitHub-hosted Chromium React Fastify PostgreSQL16"}));
 const db=await withTenant(A,tx=>tx.query(
  "SELECT count(*)::int AS n FROM api_vapt11_reports WHERE parent_assessment_id IN (SELECT parent_assessment_id FROM api_vapt11_assessments WHERE target_id=$1)",[target]));
 expect(db.rows[0].n).toBe(0);
});
