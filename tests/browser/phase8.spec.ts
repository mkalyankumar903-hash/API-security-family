import {test,expect,type APIRequestContext} from "@playwright/test";
import {readFileSync} from "node:fs";
import {randomUUID} from "node:crypto";
import {claimJob,withWorkerTenant,closeDatabase} from "../../packages/database/src/index.js";
import {processOneJob} from "../../packages/worker/src/index.js";
import {processPtDetectionJob} from "../../packages/worker/src/pt-detection.js";

const URL="http://127.0.0.1:3001",TENANT="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const headers={"authorization":"Bearer local-test-token-alpha"};
const secondTenant={"authorization":"Bearer local-test-token-beta"};
const issuer={...headers,"x-pt-authority-key":process.env.PT_TEST_AUTHORITY_KEY??""};
const source=readFileSync(new URL("../../fixtures/phase07-security.openapi.json",import.meta.url),"utf8");
test.afterAll(async()=>{await closeDatabase();});

async function seed(request:APIRequestContext){
 const suffix=randomUUID().slice(0,8);
 const target=await request.post(URL+"/v1/targets",{headers,
  data:{name:"Phase08 Browser "+suffix,environment:"SYNTHETIC",baseUrl:"https://phase08-"+suffix+".fixture.invalid"}});
 expect(target.status()).toBe(201);
 const tid=(await target.json() as {id:string}).id;
 const imported=await request.post(URL+"/v2/targets/"+tid+"/specifications/imports",{headers:{...headers,"idempotency-key":"pt8-browser-import-"+randomUUID()},
  data:{filename:"phase07-security.openapi.json",content:source}});
 expect(imported.status()).toBe(201);
 const sid=(await imported.json() as {specificationId:string}).specificationId;
 const operations=await request.get(URL+"/v2/specifications/"+sid+"/operations?limit=100",{headers});
 expect(operations.status()).toBe(200);
 const op=await operations.json() as {key:string;method:string;path:string}[];
 return {tid,sid,op};
}
async function setup(request:APIRequestContext,tid:string,sid:string,ops:string[],budget:number){
 const scoped=await request.post(URL+"/v6/pt/targets/"+tid+"/scopes",
  {headers:{...headers,"idempotency-key":"pt8-browser-scope-"+randomUUID()},
   data:{specificationId:sid,operationKeys:ops,fixtureId:"pt-security-v1",exclusions:[],
    maxEvaluations:budget,ratePerMinute:budget,maxConcurrency:1,deadlineMs:30000,validityMinutes:15}});
 expect(scoped.status()).toBe(201,await scoped.text());
 const scopeId=(await scoped.json() as {id:string}).id;
 expect((await request.post(URL+"/v6/pt/scopes/"+scopeId+"/request-authorization",{headers,data:{}})).status()).toBe(201);
 expect((await request.post(URL+"/v6/pt/test-authority/scopes/"+scopeId+"/issue",{headers,data:{}})).status()).toBe(403);
 const signed=await request.post(URL+"/v6/pt/test-authority/scopes/"+scopeId+"/issue",{headers:issuer,data:{}});
 expect(signed.status()).toBe(201,await signed.text());
 return scopeId;
}
async function admit(request:APIRequestContext,scopeId:string,rules:string[],profile:string){
 const r=await request.post(URL+"/v7/pt/scopes/"+scopeId+"/detections",
  {headers:{...headers,"idempotency-key":"pt8-browser-job-"+randomUUID()},data:{profile,ruleIds:rules}});
 expect(r.status()).toBe(201,await r.text());
 const id=(await r.json() as {id:string}).id;
 const queued=await request.get(URL+"/v7/pt/jobs/"+id,{headers});
 expect((await queued.json() as {status:string}).status).toBe("QUEUED");
 return id;
}

test("Phase08 real Chromium: partial failure after governed response yields persisted customer-readable unknown coverage",async({page,request})=>{
 test.setTimeout(150000);
 const traffic:string[]=[];
 page.on("request",r=>{if(r.url().includes(".fixture.invalid"))traffic.push(r.url());});
 const {tid,sid,op}=await seed(request);
 const key=op.find(x=>x.path==="/pt/account"&&x.method==="GET")?.key;
 expect(key).toBeTruthy();
 const scoped=await setup(request,tid,sid,[key!],2);
 const job=await admit(request,scoped,["PT-AUTH-ANONYMOUS"],"MISSING_AUTH_ENFORCEMENT");
 const claim=await claimJob();
 expect(claim?.assessment_id).toBe(job);
 await withWorkerTenant(TENANT,tx=>tx.query("UPDATE api_assessments SET status='PROCESSING' WHERE id=$1 AND status='QUEUED'",[job]));
 await processPtDetectionJob(TENANT,job,claim!.claim_token,{afterEvaluation:async count=>{
  if(count===1)throw new Error("ISOLATED_PHASE08_BROWSER_FAULT");}});
 const state=await request.get(URL+"/v7/pt/jobs/"+job,{headers});
 expect((await state.json() as {status:string}).status).toBe("FAILED");
 const diagnostics=await request.get(URL+"/v8/pt/jobs/"+job+"/terminal-coverage",{headers});
 expect(diagnostics.status()).toBe(200);
 const coverage=await diagnostics.json() as {assessmentComplete:boolean;verifiedFixed:boolean;rules:{status:string}[]};
 expect(coverage.assessmentComplete).toBe(false);
 expect(coverage.verifiedFixed).toBe(false);
 expect(coverage.rules[0]?.status).toBe("INCONCLUSIVE");
 expect((await request.get(URL+"/v7/pt/jobs/"+job+"/report",{headers})).status()).toBe(409);
 expect((await request.get(URL+"/v8/pt/jobs/"+job+"/terminal-coverage",{headers:secondTenant})).status()).toBe(404);
 await page.goto("/");
 await page.getByLabel("Select target").selectOption(tid);
 const explorer=page.getByRole("region",{name:"API PT findings and history"});
 await expect(explorer).toBeVisible();
 await explorer.getByRole("button",{name:"Refresh PT history"}).click();
 await explorer.getByRole("button",{name:/Open diagnostics/}).first().click();
 await expect(explorer.getByText(/Assessment incomplete — some security checks were not executed/)).toBeVisible();
 await expect(explorer.getByText(/PT-AUTH-ANONYMOUS · INCONCLUSIVE/)).toBeVisible();
 await expect(explorer.getByText(/No successful report exists/)).toBeVisible();
 expect(traffic).toEqual([]);
});

test("Phase08 real Chromium: multi-rule persisted report, tenant-scoped findings/history and no customer HTTP",async({page,request})=>{
 test.setTimeout(150000);
 const traffic:string[]=[];
 page.on("request",r=>{if(r.url().includes(".fixture.invalid"))traffic.push(r.url());});
 const {tid,sid,op}=await seed(request);
 const keys=op.filter(x=>x.method==="GET"&&["/pt/account","/pt/resources/bob"].includes(x.path)).map(x=>x.key);
 expect(keys.length).toBe(2);
 const scope=await setup(request,tid,sid,keys,4);
 const job=await admit(request,scope,["PT-AUTH-ANONYMOUS","PT-BOLA-CROSS-USER"],"MISSING_AUTH_ENFORCEMENT");
 expect(await processOneJob()).toBe(true);
 const progress=await request.get(URL+"/v8/pt/jobs/"+job+"/progress",{headers});
 expect(progress.status()).toBe(200);
 expect((await progress.json() as {executedEvaluations:number;plannedEvaluations:number;complete:boolean})).toMatchObject({
  executedEvaluations:4,plannedEvaluations:4,complete:true});
 const result=await request.get(URL+"/v7/pt/jobs/"+job+"/report",{headers});
 expect(result.status()).toBe(200);
 const rpt=await result.json() as {syntheticOnly:boolean;verifiedFixed:boolean;coverage:{requested:number;actualEvaluations:number};observations:{ruleId:string}[]};
 expect(rpt.syntheticOnly).toBe(true);
 expect(rpt.verifiedFixed).toBe(false);
 expect(rpt.coverage.requested).toBe(2);
 expect(rpt.coverage.actualEvaluations).toBe(4);
 expect(rpt.observations.length).toBe(1);
 expect((await request.get(URL+"/v7/pt/jobs/"+job+"/report",{headers:secondTenant})).status()).toBe(409);
 const found=await request.get(URL+"/v8/pt/findings?targetId="+tid,{headers});
 expect(found.status()).toBe(200);
 expect(((await found.json()) as {items:unknown[]}).items.length).toBe(1);
 const foreign=await request.get(URL+"/v8/pt/findings?targetId="+tid,{headers:secondTenant});
 expect(((await foreign.json()) as {items:unknown[]}).items).toHaveLength(0);
 await page.goto("/");
 await page.getByLabel("Select target").selectOption(tid);
 const explorer=page.getByRole("region",{name:"API PT findings and history"});
 await explorer.getByRole("button",{name:"Search PT findings"}).click();
 await expect(explorer.getByRole("button",{name:"Inspect evidence PT-AUTH-ANONYMOUS"})).toBeVisible();
 await explorer.getByRole("button",{name:"Inspect evidence PT-AUTH-ANONYMOUS"}).click();
 await expect(explorer.getByText(/NOT A CONFIRMED CUSTOMER VULNERABILITY/)).toBeVisible();
 await explorer.getByRole("button",{name:/Open report/}).first().click();
 await expect(explorer.getByRole("heading",{name:"Immutable report — COMPLETED"})).toBeVisible();
 await expect(explorer.getByText(/Governed synthetic evaluations: 4/)).toBeVisible();
 expect(traffic).toEqual([]);
});
