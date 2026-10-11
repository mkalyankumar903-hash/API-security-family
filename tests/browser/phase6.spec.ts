import {test,expect} from "@playwright/test";
import {drainQueue} from "../../packages/worker/src/index.js";
import {closeDatabase} from "../../packages/database/src/index.js";
test.afterAll(async()=>{await closeDatabase();});
const base="http://127.0.0.1:3001";
const auth={"authorization":"Bearer local-test-token-alpha"};
const secret=process.env.PT_TEST_AUTHORITY_KEY??"";
type Row={id:string;scope_id:string;permit_id:string;status:string};
test("Phase06 Chromium: React scope/denial/issuer/worker/receipts/report/revocation/stop/concurrency",async({page,request})=>{
 test.setTimeout(160000);
 const external:string[]=[];
 page.on("request",r=>{if(r.url().includes(".fixture.invalid"))external.push(r.url());});
 const suffix=crypto.randomUUID().slice(0,8);
 await page.goto("/");
 await page.getByPlaceholder("Payments API").fill("PT6 "+suffix);
 await page.getByPlaceholder("https://api.example.invalid").fill("https://pt6-"+suffix+".fixture.invalid");
 await page.getByRole("button",{name:"Register target"}).click();
 // A clicked submit is not a completed persisted POST. Wait for the real React
 // selected target to match this unique fixture before asserting PostgreSQL readback.
 await expect(page.locator("#target")).toHaveValue(/^[a-f0-9-]{36}$/i);
 await expect(page.locator("#target option:checked")).toContainText("PT6 "+suffix);
 const targets=await request.get(base+"/v1/targets",{headers:auth});
 const tid=(await targets.json() as {id:string;name:string}[]).find(x=>x.name==="PT6 "+suffix)?.id;
 if(!tid)throw new Error("PT_TARGET_NOT_CREATED");
 const importer=page.getByLabel(/OpenAPI 3.0 \/ 3.1, Swagger 2.0 JSON\/YAML or Postman Collection/);
 await importer.setInputFiles("fixtures/phase2-openapi30-v1.json");
 await expect(page.getByRole("status").filter({hasText:/Imported OPENAPI_3_0/})).toBeVisible();
 const pt=page.getByRole("region",{name:"API Penetration Testing authorization and safe execution"});
 await expect(pt.getByRole("heading",{name:/API Penetration Testing/})).toBeVisible();
 await pt.getByRole("button",{name:"Refresh imported versions & PT history"}).click();
 await pt.getByLabel("Imported specification for PT").selectOption({index:1});
 await expect(pt.getByRole("checkbox",{name:/GET \/status|GET \/bills/}).first()).toBeChecked();
 await pt.getByLabel("Maximum fixture evaluations").fill("6");
 await pt.getByRole("button",{name:"Propose immutable PT scope"}).click();
 await expect(pt.getByText(/CUSTOMER_PROPOSED/)).toBeVisible();
 await pt.getByRole("button",{name:"Refresh authorization and permit state"}).click();
 await expect(pt.getByText(/No permit\. Execution will be denied/)).toBeVisible();
 // Journey B: deliberate customer attempt before test-only issuer approval.
 await pt.getByRole("button",{name:"Attempt bounded fixture execution"}).click();
 await expect(pt.getByRole("alert")).toContainText("AUTHORIZATION_MISSING");
 const listed=await request.get(base+"/v6/pt/targets/"+tid+"/scopes",{headers:auth});
 expect(listed.status()).toBe(200);
 const sid=(await listed.json() as {id:string}[])[0]!.id;
 const noPermitDenials=await request.get(base+"/v6/pt/scopes/"+sid+"/denials",{headers:auth});
 expect((await noPermitDenials.json() as {code:string}[])[0]!.code).toBe("AUTHORIZATION_MISSING");
 await pt.getByRole("button",{name:"Request synthetic PT authorization"}).click();
 await expect(pt.getByText(/PENDING_TEST_AUTHORITY/)).toBeVisible();
 // Synthetic issuer is a separately authenticated CI test authority, not browser-controlled.
 const spoof=await request.post(base+"/v6/pt/test-authority/scopes/"+sid+"/issue",{headers:auth});
 expect(spoof.status()).toBe(403);
 const issue=await request.post(base+"/v6/pt/test-authority/scopes/"+sid+"/issue",
  {headers:{...auth,"x-pt-authority-key":secret},data:{}});
 expect(issue.status()).toBe(201);
 const pid=(await issue.json() as {id:string}).id;
 await pt.getByRole("button",{name:"Refresh authorization and permit state"}).click();
 await expect(pt.getByText(/SYNTHETIC FIXTURE PERMIT/)).toBeVisible();
 // Journey C: out-of-scope and non-read-only operation cannot slip past the signed permit.
 const violation=await request.post(base+"/v6/pt/scopes/"+sid+"/jobs",{
  headers:{...auth,"idempotency-key":"pt6-violate-"+crypto.randomUUID()},data:{operationKeys:["POST /status"]}});
 expect(violation.status()).toBe(409);
 expect((await violation.json() as {error:string}).error).toBe("OPERATION_OUT_OF_SCOPE");
 // Journey A: React -> Fastify -> PostgreSQL -> private worker -> trusted in-memory fixture.
 await pt.getByRole("button",{name:"Attempt bounded fixture execution"}).click();
 await expect(pt.getByText(/Status/).first()).toBeVisible();
 expect(await drainQueue()).toBe(1);
 await pt.getByRole("button",{name:"Refresh worker receipts"}).click();
 await expect(pt.getByText(/Customer-target HTTP requests: 0/)).toBeVisible();
 await expect(pt.getByRole("table",{name:"Persisted immutable evaluation receipts"})).toBeVisible();
 await expect(pt.getByRole("heading",{name:"Immutable PT authorization and fixture execution report"})).toBeVisible();
 const runs=await request.get(base+"/v6/pt/targets/"+tid+"/history",{headers:auth});
 const history=await runs.json() as Row[];
 expect(history.length).toBe(1);
 expect(history[0]!.status).toBe("COMPLETED");
 const immutableReceipts=await request.get(base+"/v6/pt/jobs/"+history[0]!.id+"/receipts",{headers:auth});
 expect(immutableReceipts.status()).toBe(200);
 const proof=await immutableReceipts.json() as {specification_version:number;scope_revision:number;permit_hash:string;evaluation_sequence:number;budget_remaining:number;decision:string}[];
 expect(proof.length).toBeGreaterThan(0);
 expect(proof.every(x=>x.specification_version>=1&&x.scope_revision>=0&&x.permit_hash.length===64&&x.evaluation_sequence>0&&x.budget_remaining>=0&&x.decision==="ALLOWED")).toBe(true);
 const report=await request.get(base+"/v6/pt/jobs/"+history[0]!.id+"/report",{headers:auth});
 const projection=await report.json() as {syntheticOnly:boolean;customerNetworkRequests:number;confirmedCustomerVulnerabilities:unknown[];verifiedFixed:boolean};
 expect(projection.syntheticOnly).toBe(true);expect(projection.customerNetworkRequests).toBe(0);
 expect(projection.confirmedCustomerVulnerabilities).toEqual([]);expect(projection.verifiedFixed).toBe(false);
 // Journey D: revoke, deny new admission, and verify UI reflects permit status.
 const revoke=await request.post(base+"/v6/pt/test-authority/permits/"+pid+"/revoke",{
  headers:{...auth,"x-pt-authority-key":secret},data:{}});
 expect(revoke.status()).toBe(200);
 await pt.getByRole("button",{name:"Refresh authorization and permit state"}).click();
 await expect(pt.getByText(/REVOKED/)).toBeVisible();
 await pt.getByRole("button",{name:"Attempt bounded fixture execution"}).click();
 await expect(pt.getByRole("alert")).toContainText("PERMIT_REVOKED");
 // Journey E: real competing admission/claim budget governor with a new scope.
 const spec=await request.get(base+"/v6/pt/scopes/"+sid,{headers:auth});
 const old=(await spec.json() as {scope:{specification_id:string;operation_keys:string[]}}).scope;
 const proposed=await request.post(base+"/v6/pt/targets/"+tid+"/scopes",{
  headers:{...auth,"idempotency-key":"pt6-concurrent-"+crypto.randomUUID()},
  data:{specificationId:old.specification_id,operationKeys:old.operation_keys,exclusions:[],
   maxEvaluations:6,maxConcurrency:1,ratePerMinute:5,deadlineMs:15000,validityMinutes:10,fixtureId:"billing-safe-v1"}});
 expect(proposed.status()).toBe(201);
 const concurrentScope=(await proposed.json() as {id:string}).id;
 expect((await request.post(base+"/v6/pt/scopes/"+concurrentScope+"/request-authorization",{headers:auth,data:{}})).status()).toBe(201);
 expect((await request.post(base+"/v6/pt/test-authority/scopes/"+concurrentScope+"/issue",
  {headers:{...auth,"x-pt-authority-key":secret},data:{}})).status()).toBe(201);
 const starts=await Promise.all(Array.from({length:4},()=>request.post(base+"/v6/pt/scopes/"+concurrentScope+"/jobs",{
  headers:{...auth,"idempotency-key":"pt6-browser-race-"+crypto.randomUUID()},data:{operationKeys:old.operation_keys}})));
 expect(starts.filter(x=>x.status()===201).length).toBe(1);
 expect(starts.filter(x=>x.status()===409).length).toBe(3);
 expect(await drainQueue()).toBe(1);
 const stop=await request.post(base+"/v6/pt/test-authority/stop",{headers:{...auth,"x-pt-authority-key":secret},data:{}});
 expect(stop.status()).toBe(200);
 await pt.getByRole("button",{name:"Refresh PT history and emergency status"}).click();
 await expect(pt.getByText(/Emergency stop: ACTIVE/)).toBeVisible();
 const resume=await request.post(base+"/v6/pt/test-authority/resume",{headers:{...auth,"x-pt-authority-key":secret},data:{}});
 expect(resume.status()).toBe(200);
 expect(external).toEqual([]);
});
