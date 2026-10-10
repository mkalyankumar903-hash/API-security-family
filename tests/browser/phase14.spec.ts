import {test,expect} from "@playwright/test";
import {randomUUID} from "node:crypto";

test("Phase14 Chromium network failure is explicit and backend recovery never fabricates Host permission",async({page,request})=>{
 const auth={authorization:"Bearer local-test-token-alpha"};
 const target=await request.post("http://127.0.0.1:3001/v1/targets",{
  headers:auth,data:{name:"Phase14 recovery "+randomUUID().slice(0,8),environment:"SYNTHETIC",
   baseUrl:"https://phase14-ui-"+randomUUID().slice(0,8)+".fixture.invalid"}});
 expect(target.status(),await target.text()).toBe(201);
 const id=(await target.json() as {id:string}).id;
 await page.route("**/v13/usage/summary",route=>route.abort("failed"));
 await page.goto("/");
 await page.getByLabel("Select target").selectOption(id);
 const section=page.locator("#phase13-commercial");
 await expect(section.getByRole("alert")).toContainText("TRANSPORT_OR_TIMEOUT");
 await expect(section.getByText("Host authority:",{exact:false})).toHaveCount(0);
 await expect(section.getByText("NOT CONFIGURED")).toHaveCount(0);
 await page.unroute("**/v13/usage/summary");
 await page.reload();
 await page.getByLabel("Select target").selectOption(id);
 await expect(section.getByText("HOST_AUTHORITY_NOT_CONFIGURED")).toBeVisible();
 await expect(section.getByRole("alert")).toHaveCount(0);
 const decision=await request.get("http://127.0.0.1:3001/v13/decisions",{headers:auth});
 expect(decision.status()).toBe(200);
 expect((await decision.json() as {allowed:boolean}).allowed).toBe(false);
});

test("Phase14 real Chromium keyboard navigation, 320px, 200% zoom, pseudo-RTL and reduced-motion authority",async({page,request})=>{
 const auth={authorization:"Bearer local-test-token-alpha"};
 const create=async()=>{
  const response=await request.post("http://127.0.0.1:3001/v1/targets",{headers:auth,data:{
   name:"Phase14 A11y "+randomUUID().slice(0,8),environment:"SYNTHETIC",
   baseUrl:"https://phase14-a11y-"+randomUUID().slice(0,8)+".fixture.invalid"}});
  expect(response.status(),await response.text()).toBe(201);
  return (await response.json() as {id:string}).id;
 };
 const old=await create(),current=await create();
 await page.setViewportSize({width:320,height:700});
 await page.emulateMedia({reducedMotion:"reduce"});
 await page.goto("/");
 await page.getByLabel("Select target").selectOption(old);
 const panel=page.locator("#phase13-commercial");
 await expect(panel.getByRole("heading",{level:2})).toBeVisible();
 const combo=panel.getByLabel("Commercial QA locale");
 await combo.focus();
 await expect(combo).toBeFocused();
 await page.keyboard.press("ArrowDown");
 await expect(combo).toHaveValue("en-XA");
 await combo.selectOption("en-XB");
 await expect(panel).toHaveAttribute("dir","rtl");
 await page.evaluate(()=>{document.documentElement.style.fontSize="200%";});
 await expect(panel.getByRole("table",{name:"Observed report capacity — not a bill or subscription"})).toBeVisible();
 await expect(panel.getByRole("heading",{level:2})).toBeVisible();
 expect(await page.evaluate(()=>matchMedia("(prefers-reduced-motion: reduce)").matches)).toBe(true);
 await page.getByLabel("Select target").selectOption(current);
 await expect(panel).toContainText(current.slice(0,12));
 await expect(panel).not.toContainText(old.slice(0,12));
 await page.getByLabel("Synthetic development token (never a production login)").fill("local-test-token-beta");
 await expect(panel).toHaveCount(0);
});
test("Phase14 Chromium server 429, 503 and recovery never show stale commercial entitlement",async({page,request})=>{
 const created=await request.post("http://127.0.0.1:3001/v1/targets",{
  headers:{authorization:"Bearer local-test-token-alpha"},data:{
   name:"Phase14 quota "+randomUUID().slice(0,8),environment:"SYNTHETIC",
   baseUrl:"https://phase14-rate-"+randomUUID().slice(0,8)+".fixture.invalid"}});
 expect(created.status()).toBe(201);
 const id=(await created.json() as {id:string}).id;
 for(const status of [429,503]){
  await page.route("**/v13/usage/summary",route=>route.fulfill({status,
   contentType:"application/json",body:JSON.stringify({error:status===429?"QUEUE_TENANT_CAPACITY_EXCEEDED":"HOST_UNAVAILABLE"})}));
  await page.goto("/");
  await page.getByLabel("Select target").selectOption(id);
  const panel=page.locator("#phase13-commercial");
  await expect(panel.getByRole("alert")).toContainText(status===429?"QUEUE_TENANT_CAPACITY_EXCEEDED":"HOST_UNAVAILABLE");
  await expect(panel.getByText("HOST_AUTHORITY_NOT_CONFIGURED")).toHaveCount(0);
  await page.unroute("**/v13/usage/summary");
  await page.reload();
  await page.getByLabel("Select target").selectOption(id);
  await expect(panel.getByText("HOST_AUTHORITY_NOT_CONFIGURED")).toBeVisible();
  await expect(panel.getByRole("alert")).toHaveCount(0);
 }
});
