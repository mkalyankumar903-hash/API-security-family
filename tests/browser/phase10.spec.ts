import {test,expect} from "@playwright/test";
import {readFileSync} from "node:fs";
import {randomUUID} from "node:crypto";
import {processOneJob} from "../../packages/worker/src/index.js";
import {closeDatabase} from "../../packages/database/src/index.js";

const API="http://127.0.0.1:3001";
const user={authorization:"Bearer local-test-token-alpha"};
const other={authorization:"Bearer local-test-token-beta"};
const trusted={...user,"x-pt-authority-key":process.env.PT_TEST_AUTHORITY_KEY??""};
const input=readFileSync(new URL("../../fixtures/phase07-security.openapi.json",import.meta.url),"utf8");
test.afterAll(async()=>{await closeDatabase();});

test("Phase10 Chromium: real persisted worker attempts, lease status and immutable synthetic report",async({page,request})=>{
 test.setTimeout(150000);
 const seen:string[]=[];
 page.on("request",r=>{if(r.url().endsWith(".fixture.invalid")||r.url().includes("pt10-"))seen.push(r.url());});
 const suffix=randomUUID().slice(0,8);
 const target=await request.post(API+"/v1/targets",{headers:user,
  data:{name:"Phase10 "+suffix,environment:"SYNTHETIC",baseUrl:"https://pt10-"+suffix+".fixture.invalid"}});
 expect(target.status(),await target.text()).toBe(201);
 const targetId=(await target.json() as {id:string}).id;
 const imported=await request.post(API+"/v2/targets/"+targetId+"/specifications/imports",{
  headers:{...user,"idempotency-key":"pt10-import-"+randomUUID()},
  data:{filename:"phase07-security.openapi.json",content:input}});
 expect(imported.status(),await imported.text()).toBe(201);
 const specId=(await imported.json() as {specificationId:string}).specificationId;
 const operations=await request.get(API+"/v2/specifications/"+specId+"/operations?limit=100",{headers:user});
 expect(operations.status()).toBe(200);
 const keys=(await operations.json() as {key:string;method:string;path:string}[])
  .filter(x=>x.method==="GET"&&["/pt/account","/pt/resources/bob","/pt/admin","/pt/confidential"].includes(x.path))
  .map(x=>x.key);
 expect(keys).toHaveLength(4);
 const scope=await request.post(API+"/v6/pt/targets/"+targetId+"/scopes",{
  headers:{...user,"idempotency-key":"pt10-scope-"+randomUUID()},
  data:{specificationId:specId,operationKeys:keys,fixtureId:"pt-security-v1",exclusions:[],
   maxEvaluations:14,ratePerMinute:14,maxConcurrency:1,deadlineMs:30000,validityMinutes:15}});
 expect(scope.status(),await scope.text()).toBe(201);
 const scopeId=(await scope.json() as {id:string}).id;
 expect((await request.post(API+"/v6/pt/scopes/"+scopeId+"/request-authorization",{headers:user,data:{}})).status()).toBe(201);
 const permit=await request.post(API+"/v6/pt/test-authority/scopes/"+scopeId+"/issue",{headers:trusted,data:{}});
 expect(permit.status(),await permit.text()).toBe(201);
 await page.goto("/");
 await page.getByLabel("Select target").selectOption(targetId);
 const panel=page.getByRole("region",{name:"Autonomous API security orchestration"});
 await expect(panel.getByText("ISOLATED SYNTHETIC API SECURITY EXECUTION")).toBeVisible();
 await expect(panel.getByText("REAL CUSTOMER API TESTING NOT AUTHORIZED")).toBeVisible();
 await expect(panel.getByText("WORKER RECOVERY DOES NOT GRANT NEW SECURITY AUTHORITY")).toBeVisible();
 await panel.getByLabel("Approved synthetic scope").selectOption(scopeId);
 await expect(panel.getByText("Authorization readiness: VALID",{exact:false})).toBeVisible();
 await panel.getByRole("button",{name:"Start authorized orchestration"}).click();
 await expect(panel.getByText("Persisted orchestration progress")).toBeVisible();
 const history=await request.get(API+"/v9/pt/targets/"+targetId+"/history",{headers:user});
 expect(history.status()).toBe(200);
 const jid=(await history.json() as {id:string}[])[0]!.id;
 const queued=await request.get(API+"/v10/workers/assessments/"+jid+"/execution",{headers:user});
 expect(queued.status()).toBe(200);
 expect((await queued.json() as {queue:{queueState:string}}).queue.queueState).toBe("QUEUED");
 expect(await processOneJob()).toBe(true);
 await expect(panel.getByText("Immutable completed synthetic report")).toBeVisible({timeout:30000});
 const details=await request.get(API+"/v10/workers/assessments/"+jid+"/execution",{headers:user});
 expect(details.status()).toBe(200);
 const data=await details.json() as {queue:null;attempts:{state:string;claim_generation:number}[];
  events:{kind:string}[];assessment:{status:string};realCustomerApiTestingAuthorized:boolean};
 expect(data.queue).toBe(null);
 expect(data.assessment.status).toBe("COMPLETED");
 expect(data.attempts).toHaveLength(1);
 expect(data.attempts[0]!.state).toBe("COMPLETED");
 expect(data.attempts[0]!.claim_generation).toBe(1);
 expect(data.events.some(x=>x.kind==="CLAIMED")).toBe(true);
 expect(data.events.some(x=>x.kind==="COMPLETED")).toBe(true);
 expect(data.realCustomerApiTestingAuthorized).toBe(false);
 const displayed=panel.getByRole("article",{name:"Worker execution safety diagnostics"});
 await expect(displayed.getByText("Generation 1",{exact:false})).toBeVisible();
 expect((await request.get(API+"/v10/workers/assessments/"+jid+"/execution",{headers:other})).status()).toBe(404);
 expect(seen).toEqual([]);
});
