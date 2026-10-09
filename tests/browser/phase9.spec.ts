import {test,expect,type APIRequestContext} from "@playwright/test";
import {readFileSync} from "node:fs";
import {randomUUID} from "node:crypto";
import {processOneJob} from "../../packages/worker/src/index.js";
import {closeDatabase} from "../../packages/database/src/index.js";

const API="http://127.0.0.1:3001",tenant={"authorization":"Bearer local-test-token-alpha"};
const other={"authorization":"Bearer local-test-token-beta"};
const issuer={...tenant,"x-pt-authority-key":process.env.PT_TEST_AUTHORITY_KEY??""};
const source=readFileSync(new URL("../../fixtures/phase07-security.openapi.json",import.meta.url),"utf8");
test.afterAll(async()=>{await closeDatabase();});
async function seed(request:APIRequestContext,profileBudget=14){
 const suffix=randomUUID().slice(0,8);
 const target=await request.post(API+"/v1/targets",{headers:tenant,
  data:{name:"Phase09 Browser "+suffix,environment:"SYNTHETIC",baseUrl:"https://pt9-"+suffix+".fixture.invalid"}});
 expect(target.status(),await target.text()).toBe(201);
 const tid=(await target.json() as {id:string}).id;
 const imp=await request.post(API+"/v2/targets/"+tid+"/specifications/imports",{
  headers:{...tenant,"idempotency-key":"pt9-browser-import-"+randomUUID()},
  data:{filename:"phase07-security.openapi.json",content:source}});
 expect(imp.status(),await imp.text()).toBe(201);
 const specId=(await imp.json() as {specificationId:string}).specificationId;
 const operations=await request.get(API+"/v2/specifications/"+specId+"/operations?limit=100",{headers:tenant});
 expect(operations.status()).toBe(200);
 const ops=await operations.json() as {key:string;path:string;method:string}[];
 const paths=["/pt/account","/pt/resources/bob","/pt/admin","/pt/confidential"];
 const keys=paths.map(path=>ops.find(x=>x.method==="GET"&&x.path===path)?.key);
 expect(keys.every(Boolean)).toBeTruthy();
 const scoped=await request.post(API+"/v6/pt/targets/"+tid+"/scopes",{
  headers:{...tenant,"idempotency-key":"pt9-browser-scope-"+randomUUID()},
  data:{specificationId:specId,operationKeys:keys,fixtureId:"pt-security-v1",exclusions:[],
   maxEvaluations:profileBudget,ratePerMinute:profileBudget,maxConcurrency:1,deadlineMs:30000,validityMinutes:15}});
 expect(scoped.status(),await scoped.text()).toBe(201);
 const scopeId=(await scoped.json() as {id:string}).id;
 expect((await request.post(API+"/v6/pt/scopes/"+scopeId+"/request-authorization",{headers:tenant,data:{}})).status()).toBe(201);
 const issued=await request.post(API+"/v6/pt/test-authority/scopes/"+scopeId+"/issue",{headers:issuer,data:{}});
 expect(issued.status(),await issued.text()).toBe(201);
 const permitId=(await issued.json() as {id:string}).id;
 return {tid,specId,scopeId,permitId};
}
async function select(page:import("@playwright/test").Page,tid:string){
 await page.goto("/");
 await page.getByLabel("Select target").selectOption(tid);
 const panel=page.getByRole("region",{name:"Autonomous API security orchestration"});
 await expect(panel).toBeVisible();
 await expect(panel.getByText("ISOLATED SYNTHETIC AUTONOMOUS API PT")).toBeVisible();
 await expect(panel.getByText("NOT AUTHORIZED FOR LIVE CUSTOMER API TESTING")).toBeVisible();
 await expect(panel.getByText("REAL HOST AUTHORIZATION UNAVAILABLE")).toBeVisible();
 return panel;
}
test("Phase09 real Chromium: complete six-stage governed automatic journey with customer UI and immutable report",async({page,request})=>{
 test.setTimeout(150000);
 const outside:string[]=[];
 page.on("request",r=>{if(r.url().includes(".fixture.invalid"))outside.push(r.url());});
 const {tid,scopeId}=await seed(request);
 const panel=await select(page,tid);
 await panel.getByLabel("Approved synthetic scope").selectOption(scopeId);
 await expect(panel.getByText("Immutable execution plan preview")).toBeVisible();
 await expect(panel.getByText("Planned evaluations: 14", {exact:false})).toBeVisible();
 await expect(panel.getByText("Authorization readiness: VALID",{exact:false})).toBeVisible();
 await expect(panel.getByRole("listitem").filter({hasText:"FINALIZATION"}).first()).toBeVisible();
 await panel.getByRole("button",{name:"Start authorized orchestration"}).click();
 await expect(panel.getByText("Persisted orchestration progress")).toBeVisible();
 expect(await processOneJob()).toBe(true);
 await expect(panel.getByText("Immutable completed synthetic report")).toBeVisible({timeout:30000});
 await expect(panel.getByText("8 PASS", {exact:false})).toBeVisible();
 await expect(panel.getByText("14/14", {exact:false})).toBeVisible();
 const history=await request.get(API+"/v9/pt/targets/"+tid+"/history?limit=10",{headers:tenant});
 expect(history.status()).toBe(200);
 const runs=await history.json() as {id:string;status:string}[];
 expect(runs.some(x=>x.status==="COMPLETED")).toBe(true);
 const report=await request.get(API+"/v9/pt/orchestrations/"+runs[0]!.id+"/report",{headers:tenant});
 expect(report.status()).toBe(200);
 const data=await report.json() as {syntheticOnly:boolean;customerNetworkRequests:number;verifiedFixed:boolean;accounting:{executed:number}};
 expect(data.syntheticOnly).toBe(true);expect(data.customerNetworkRequests).toBe(0);
 expect(data.verifiedFixed).toBe(false);expect(data.accounting.executed).toBe(14);
 expect((await request.get(API+"/v9/pt/orchestrations/"+runs[0]!.id,{headers:other})).status()).toBe(404);
 expect(outside).toEqual([]);
});
test("Phase09 real Chromium: signed synthetic revocation blocks downstream stages and shows truthful terminal diagnostics",async({page,request})=>{
 test.setTimeout(150000);
 const {tid,scopeId,permitId}=await seed(request,4);
 const panel=await select(page,tid);
 await panel.getByLabel("Approved synthetic scope").selectOption(scopeId);
 await panel.getByLabel("Trusted policy profile").selectOption("SYNTHETIC_PT_AUTHORIZATION_FOCUSED");
 await expect(panel.getByText("Planned evaluations: 4",{exact:false})).toBeVisible();
 await panel.getByRole("button",{name:"Start authorized orchestration"}).click();
 const history=await request.get(API+"/v9/pt/targets/"+tid+"/history",{headers:tenant});
 const runs=await history.json() as {id:string}[];
 const jid=runs[0]!.id;
 const revoke=await request.post(API+"/v6/pt/test-authority/permits/"+permitId+"/revoke",{headers:issuer,data:{}});
 expect(revoke.status()).toBe(200);
 expect(await processOneJob()).toBe(true);
 await expect(panel.getByText("Terminal diagnostic — not a successful PT report")).toBeVisible({timeout:30000});
 expect((await request.get(API+"/v9/pt/orchestrations/"+jid+"/report",{headers:tenant})).status()).toBe(409);
 const diagnostic=await request.get(API+"/v9/pt/orchestrations/"+jid+"/terminal",{headers:tenant});
 expect(diagnostic.status()).toBe(200);
 expect((await diagnostic.json() as {assessmentComplete:boolean}).assessmentComplete).toBe(false);
});
