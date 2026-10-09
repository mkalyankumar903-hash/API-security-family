import {test,expect} from "@playwright/test";
import {readFileSync} from "node:fs";
import {drainQueue} from "../../packages/worker/src/index.js";
import {closeDatabase} from "../../packages/database/src/index.js";
test.afterAll(async()=>{await closeDatabase();});
const url="http://127.0.0.1:3001";
const auth={"authorization":"Bearer local-test-token-alpha"};
const signer=process.env.PT_TEST_AUTHORITY_KEY??"";
test("Phase07 real Chromium: protected fixture weakness, secure negative, permit boundary, history and no customer network",async({page,request})=>{
 test.setTimeout(160000);
 const external:string[]=[];
 page.on("request",r=>{if(r.url().endsWith(".fixture.invalid")||r.url().includes(".fixture.invalid/"))external.push(r.url());});
 const suffix=crypto.randomUUID().slice(0,8);
 await page.goto("/");
 await page.getByPlaceholder("Payments API").fill("PT7 "+suffix);
 await page.getByPlaceholder("https://api.example.invalid").fill("https://phase07-"+suffix+".fixture.invalid");
 const targetCreated=page.waitForResponse(r=>r.request().method()==="POST"&&r.url()===url+"/v1/targets");
 await page.getByRole("button",{name:"Register target"}).click();
 const targetResponse=await targetCreated;
 const targetBody=await targetResponse.json() as {id?:string;error?:string};
 expect(targetResponse.status(),targetBody.error).toBe(201);
 const tid=targetBody.id!;
 expect(tid).toMatch(/^[a-f0-9-]{36}$/i);
 await expect(page.getByLabel("Select target")).toHaveValue(tid);
 const uploader=page.getByLabel(/OpenAPI 3.0 \/ 3.1, Swagger 2.0 JSON\/YAML or Postman Collection/);
 await uploader.setInputFiles("fixtures/phase07-security.openapi.json");
 await expect(page.getByRole("status").filter({hasText:/Imported OPENAPI_3_0/})).toBeVisible();
 const panel=page.getByRole("region",{name:"API PT deterministic detection assessment"});
 await expect(panel.getByText(/NOT CUSTOMER PRODUCTION VULNERABILITY VERIFICATION/)).toBeVisible();
 await panel.getByRole("button",{name:"Refresh detection catalog & history"}).click();
 await panel.getByLabel("PT detection specification").selectOption({index:1});
 await panel.getByLabel("PT detection fixture profile").selectOption("CROSS_USER_ACCESS_WEAKNESS");
 await panel.getByRole("checkbox",{name:/PT-BOLA-CROSS-USER/}).check();
 await expect(panel.getByText(/Signed-permit evaluation budget preview/)).toContainText("2");
 const firstProposed=page.waitForResponse(r=>r.request().method()==="POST"&&
  r.url()===url+"/v6/pt/targets/"+tid+"/scopes");
 await panel.getByRole("button",{name:"Propose detection scope"}).click();
 const firstScopeResponse=await firstProposed;
 expect(firstScopeResponse.status()).toBe(201);
 const sid=(await firstScopeResponse.json() as {id:string}).id;
 await expect(panel.getByText("Scope: "+sid)).toBeVisible();
 const scoped=await request.get(url+"/v6/pt/targets/"+tid+"/scopes",{headers:auth});
 expect(scoped.status()).toBe(200);
 expect((await scoped.json() as {id:string}[]).some(x=>x.id===sid)).toBe(true);
 const before=await request.post(url+"/v7/pt/scopes/"+sid+"/detections",{
  headers:{...auth,"idempotency-key":"pt7-deny-"+crypto.randomUUID()},
  data:{profile:"CROSS_USER_ACCESS_WEAKNESS",ruleIds:["PT-BOLA-CROSS-USER"]}});
 expect(before.status()).toBe(409);
 expect((await before.json() as {error:string}).error).toBe("AUTHORIZATION_MISSING");
 await panel.getByRole("button",{name:"Request separate synthetic test authority"}).click();
 const spoof=await request.post(url+"/v6/pt/test-authority/scopes/"+sid+"/issue",{headers:auth,data:{}});
 expect(spoof.status()).toBe(403);
 const signed=await request.post(url+"/v6/pt/test-authority/scopes/"+sid+"/issue",
  {headers:{...auth,"x-pt-authority-key":signer},data:{}});
 expect(signed.status()).toBe(201);
 await panel.getByRole("button",{name:"Refresh detection permit"}).click();
 await expect(panel.getByText("TEST-ONLY PERMIT ISSUED")).toBeVisible();
 // The React click launches an asynchronous POST; a Playwright click does not await its commit.
 // Synchronize on the exact scope-bound admission response before draining the private queue.
 const submitDetection=async(scopeId:string):Promise<string>=>{
  const admitted=page.waitForResponse(r=>r.request().method()==="POST"&&
   r.url()===url+"/v7/pt/scopes/"+scopeId+"/detections");
  await panel.getByRole("button",{name:"Start governed detection assessment"}).click();
  const response=await admitted;
  const payload=await response.json() as {id?:string;status?:string;error?:string};
  expect(response.status(),JSON.stringify({scopeId,status:response.status(),error:payload.error})).toBe(201);
  expect(payload.status).toBe("QUEUED");
  expect(payload.id).toMatch(/^[a-f0-9-]{36}$/i);
  const persisted=await request.get(url+"/v7/pt/jobs/"+payload.id,{headers:auth});
  expect(persisted.status()).toBe(200);
  const state=await persisted.json() as {id:string;scope_id:string;status:string};
  expect(state.id).toBe(payload.id);
  expect(state.scope_id).toBe(scopeId);
  expect(state.status).toBe("QUEUED");
  return payload.id!;
 };
 const vulnerableId=await submitDetection(sid);
 expect(await drainQueue(1)).toBe(1);
 expect((await (await request.get(url+"/v7/pt/jobs/"+vulnerableId,{headers:auth})).json() as {status:string}).status).toBe("COMPLETED");
 await panel.getByRole("button",{name:"Refresh detection results"}).click();
 await expect(panel.getByText(/Synthetic observations 1/)).toBeVisible();
 await expect(panel.getByText(/PT-BOLA-CROSS-USER · HIGH · HIGH/)).toBeVisible();
 await panel.getByText("Redacted observed evidence").click();
 await expect(panel.getByText(/alice · \/pt\/resources\/bob · HTTP 200/)).toBeVisible();
 await expect(panel.getByText(/VERIFIED_FIXED: false/)).toBeVisible();
 const first=await request.get(url+"/v7/pt/targets/"+tid+"/history",{headers:auth});
 const firstJob=(await first.json() as {id:string}[])[0]!.id;
 const firstReport=await request.get(url+"/v7/pt/jobs/"+firstJob+"/report",{headers:auth});
 expect((await firstReport.json() as {observations:unknown[]}).observations.length).toBe(1);
 const backed=await request.get(url+"/v7/pt/jobs/"+firstJob+"/evaluations",{headers:auth});
 expect(backed.status()).toBe(200);
 const actual=await backed.json() as {state:string;evidence:{responseHash:string}|null}[];
 expect(actual.length).toBe(2);
 expect(actual.every(x=>x.state==="CONSUMED"&&x.evidence?.responseHash?.length===64)).toBe(true);
 expect(backed.body().then(x=>x.toString("utf8").includes("SYNTHETIC_PLACEHOLDER_NOT_A_SECRET"))).resolves.toBe(false);
 await panel.getByRole("button",{name:"Export persisted JSON report"}).click();
 // Secure fixture: identical trusted operation/rule but a different signed scope and new test-only permit.
 await panel.getByLabel("PT detection fixture profile").selectOption("SECURE_BASELINE");
 const secondProposed=page.waitForResponse(r=>r.request().method()==="POST"&&
  r.url()===url+"/v6/pt/targets/"+tid+"/scopes");
 await panel.getByRole("button",{name:"Propose detection scope"}).click();
 const secondScopeResponse=await secondProposed;
 expect(secondScopeResponse.status()).toBe(201);
 const newScope=(await secondScopeResponse.json() as {id:string}).id;
 expect(newScope).not.toBe(sid);
 await expect(panel.getByText("Scope: "+newScope)).toBeVisible();
 await panel.getByRole("button",{name:"Request separate synthetic test authority"}).click();
 expect((await request.post(url+"/v6/pt/test-authority/scopes/"+newScope+"/issue",
  {headers:{...auth,"x-pt-authority-key":signer},data:{}})).status()).toBe(201);
 await panel.getByRole("button",{name:"Refresh detection permit"}).click();
 const secureId=await submitDetection(newScope);
 expect(await drainQueue(1)).toBe(1);
 expect((await (await request.get(url+"/v7/pt/jobs/"+secureId,{headers:auth})).json() as {status:string}).status).toBe("COMPLETED");
 await panel.getByRole("button",{name:"Refresh detection results"}).click();
 await expect(panel.getByText(/Synthetic observations 0/)).toBeVisible();
 await expect(panel.getByText(/No synthetic weakness observed/)).toBeVisible();
 const after=await request.get(url+"/v7/pt/targets/"+tid+"/history",{headers:auth});
 const secondJob=(await after.json() as {id:string}[]).find(x=>x.id!==firstJob)!.id;
 const compare=await request.get(url+"/v7/pt/jobs/"+firstJob+"/compare/"+secondJob,{headers:auth});
 expect(compare.status()).toBe(200);
 expect((await compare.json() as {compatibility:string;verifiedFixed:boolean}).compatibility).toBe("COMPATIBLE");
 expect((await compare.json() as {verifiedFixed:boolean}).verifiedFixed).toBe(false);
 expect((await request.get(url+"/v7/pt/jobs/"+firstJob+"/report",{
  headers:{authorization:"Bearer local-test-token-beta"}})).status()).toBe(409);
 // Cancellation and stop must prevent all queued synthetic fixture evaluations.
 const additionalScope=async():Promise<string>=>{
  const received=page.waitForResponse(r=>r.request().method()==="POST"&&
   r.url()===url+"/v6/pt/targets/"+tid+"/scopes");
  await panel.getByRole("button",{name:"Propose detection scope"}).click();
  const response=await received,payload=await response.json() as {id?:string;error?:string};
  expect(response.status(),payload.error).toBe(201);
  expect(payload.id).toBeTruthy();
  return payload.id!;
 };
 const authorizeAdditional=async(scopeId:string):Promise<void>=>{
  const authorized=page.waitForResponse(r=>r.request().method()==="POST"&&
   r.url()===url+"/v6/pt/scopes/"+scopeId+"/request-authorization");
  await panel.getByRole("button",{name:"Request separate synthetic test authority"}).click();
  expect((await authorized).status()).toBe(201);
  const signed=await request.post(url+"/v6/pt/test-authority/scopes/"+scopeId+"/issue",{
   headers:{...auth,"x-pt-authority-key":signer},data:{}
  });
  expect(signed.status()).toBe(201);
  await panel.getByRole("button",{name:"Refresh detection permit"}).click();
  await expect(panel.getByText("TEST-ONLY PERMIT ISSUED")).toBeVisible();
 };
 const cancellationScope=await additionalScope();
 await authorizeAdditional(cancellationScope);
 const cancelledId=await submitDetection(cancellationScope);
 await expect(panel.getByRole("button",{name:"Cancel detection"})).toBeEnabled();
 const cancelled=page.waitForResponse(r=>r.request().method()==="POST"&&
  r.url()===url+"/v6/pt/jobs/"+cancelledId+"/cancel");
 await panel.getByRole("button",{name:"Cancel detection"}).click();
 expect((await cancelled).status()).toBe(200);
 expect((await (await request.get(url+"/v7/pt/jobs/"+cancelledId,{headers:auth})).json() as {status:string}).status).toBe("CANCELLED");
 expect((await request.get(url+"/v7/pt/jobs/"+cancelledId+"/report",{headers:auth})).status()).toBe(409);
 expect((await (await request.get(url+"/v7/pt/jobs/"+cancelledId+"/evaluations",{headers:auth})).json() as unknown as unknown[]).length).toBe(0);
 const stopScope=await additionalScope();
 await authorizeAdditional(stopScope);
 const stoppedId=await submitDetection(stopScope);
 expect((await request.post(url+"/v6/pt/test-authority/stop",{headers:auth,data:{}})).status()).toBe(403);
 expect((await request.post(url+"/v6/pt/test-authority/stop",{
  headers:{...auth,"x-pt-authority-key":signer},data:{}
 })).status()).toBe(200);
 expect((await (await request.get(url+"/v7/pt/jobs/"+stoppedId,{headers:auth})).json() as {status:string}).status).toBe("CANCELLED");
 expect((await request.get(url+"/v7/pt/jobs/"+stoppedId+"/report",{headers:auth})).status()).toBe(409);
 expect((await (await request.get(url+"/v7/pt/jobs/"+stoppedId+"/evaluations",{headers:auth})).json() as unknown as unknown[]).length).toBe(0);
 expect((await request.post(url+"/v6/pt/test-authority/resume",{
  headers:{...auth,"x-pt-authority-key":signer},data:{}
 })).status()).toBe(200);
 // An imported synthetic POST operation can never be admitted into a trusted read-only scope.
 const syntheticSpec=JSON.parse(readFileSync("fixtures/phase07-security.openapi.json","utf8")) as {
  paths:Record<string,Record<string,unknown>>
 };
 syntheticSpec.paths["/pt/account"]!.post={operationId:"synthetic_forbidden_post",
  responses:{"200":{description:"Not executable by the PT governor"}}};
 const imported=await request.post(url+"/v2/targets/"+tid+"/specifications/imports",{
  headers:{...auth,"idempotency-key":"pt7-unsafe-import-"+crypto.randomUUID()},
  data:{filename:"phase07-method-denial.openapi.json",content:JSON.stringify(syntheticSpec)}
 });
 expect(imported.status()).toBe(201);
 const unsafeSpecId=(await imported.json() as {specificationId:string}).specificationId;
 const opResponse=await request.get(url+"/v2/specifications/"+unsafeSpecId+"/operations?limit=100",{headers:auth});
 expect(opResponse.status()).toBe(200);
 const postOp=(await opResponse.json() as {key:string;path:string;method:string}[])
  .find(x=>x.method==="POST"&&x.path==="/pt/account");
 expect(postOp).toBeDefined();
 const forbidden=await request.post(url+"/v6/pt/targets/"+tid+"/scopes",{
  headers:{...auth,"idempotency-key":"pt7-unsafe-scope-"+crypto.randomUUID()},
  data:{specificationId:unsafeSpecId,operationKeys:[postOp!.key],fixtureId:"pt-security-v1",exclusions:[],
   maxEvaluations:1,maxConcurrency:1,ratePerMinute:1,deadlineMs:30000,validityMinutes:15}
 });
 expect(forbidden.status()).toBe(409);
 expect((await forbidden.json() as {error:string}).error).toBe("METHOD_DENIED");
 expect(external).toEqual([]);
});
