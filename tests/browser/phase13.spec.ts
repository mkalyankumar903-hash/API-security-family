import {test,expect} from "@playwright/test";
import {randomUUID} from "node:crypto";
test("Phase13 Chromium commercial workspace remains host-blocked, scoped and accessible",async({page,request})=>{
 const target=await request.post("http://127.0.0.1:3001/v1/targets",{
  headers:{authorization:"Bearer local-test-token-alpha"},data:{
   name:"Phase13 browser "+randomUUID().slice(0,6),
   environment:"SYNTHETIC",baseUrl:"https://phase13-browser-"+randomUUID().slice(0,8)+".fixture.invalid"}});
 expect(target.status(),await target.text()).toBe(201);
 const {id}=await target.json() as {id:string};
 await page.goto("/");
 await page.getByLabel("Select target").selectOption(id);
 const section=page.locator("#phase13-commercial");
 await expect(section.getByRole("heading",{name:"Commercial usage & entitlements — Phase 13"})).toBeVisible();
 const directSummary=await request.get("http://127.0.0.1:3001/v13/usage/summary",{headers:{authorization:"Bearer local-test-token-alpha"}});
 expect(directSummary.status(),await directSummary.text()).toBe(200);
 expect((await directSummary.json() as {hostAuthority:string}).hostAuthority).toBe("HOST_AUTHORITY_NOT_CONFIGURED");
 await expect(section.getByText("HOST_AUTHORITY_NOT_CONFIGURED")).toBeVisible();
 await expect(section.getByText("NOT CONFIGURED")).toBeVisible();
 await expect(section.getByText("PENDING_EXTERNAL_AUTHORITY")).toBeVisible();
 await expect(section.getByRole("table",{name:"Observed report capacity — not a bill or subscription"})).toBeVisible();
 const resp=await request.get("http://127.0.0.1:3001/v13/decisions",{headers:{authorization:"Bearer local-test-token-alpha"}});
 expect(resp.status()).toBe(200);expect((await resp.json() as {allowed:boolean}).allowed).toBe(false);
 await page.getByLabel("Commercial QA locale").selectOption("en-XB");
 await expect(section).toHaveAttribute("dir","rtl");
 await expect(section.getByRole("heading",{name:"⟦Commercial usage & entitlements — Phase 13⟧"})).toBeVisible();
 await expect(section.getByText("HOST_AUTHORITY_NOT_CONFIGURED")).toBeVisible();
 await page.getByLabel("Commercial QA locale").selectOption("en-XA");
 await expect(section).toHaveAttribute("dir","ltr");
 await expect(section.getByRole("heading",{level:2})).toContainText("⟦");
 await page.getByLabel("Synthetic development token (never a production login)").fill("local-test-token-beta");
 await expect(section).toHaveCount(0);
});

test("Phase13 real Chromium keyboard, narrow layout, 200-percent text, RTL, reduced motion and tenant-switch stale rejection",async({page,request})=>{
 const auth={authorization:"Bearer local-test-token-alpha"};
 const seed=async()=>{
  const r=await request.post("http://127.0.0.1:3001/v1/targets",{headers:auth,data:{
   name:"Phase13 accessible "+randomUUID().slice(0,8),environment:"SYNTHETIC",
   baseUrl:"https://phase13-a11y-"+randomUUID().slice(0,8)+".fixture.invalid"}});
  expect(r.status(),await r.text()).toBe(201);
  return (await r.json() as {id:string}).id;
 };
 const old=await seed(),next=await seed();
 await page.setViewportSize({width:360,height:740});
 await page.emulateMedia({reducedMotion:"reduce"});
 await page.goto("/");
 await page.getByLabel("Select target").selectOption(old);
 const section=page.locator("#phase13-commercial");
 await expect(section).toBeVisible();
 await expect(section).toContainText(old.slice(0,12));
 const selector=section.locator("#phase13-locale");
 await selector.focus();
 await expect(selector).toBeFocused();
 await page.keyboard.press("ArrowDown");
 await expect(selector).toHaveValue("en-XA");
 await expect(section.getByRole("heading",{level:2})).toContainText("⟦");
 await selector.selectOption("en-XB");
 await expect(section).toHaveAttribute("dir","rtl");
 await expect(section.getByRole("table",{name:"Observed report capacity — not a bill or subscription"})).toBeVisible();
 await expect(section.locator("th[scope='col']")).toHaveCount(5);
 expect(await page.evaluate(()=>matchMedia("(prefers-reduced-motion: reduce)").matches)).toBe(true);
 await page.evaluate(()=>{document.documentElement.style.fontSize="200%";});
 await expect(section.getByRole("heading",{level:2})).toBeVisible();
 await expect(section.getByRole("table",{name:"Observed report capacity — not a bill or subscription"})).toBeVisible();
 await page.getByLabel("Select target").selectOption(next);
 await expect(section).toContainText(next.slice(0,12));
 await expect(section).not.toContainText(old.slice(0,12));
 const check=await request.get("http://127.0.0.1:3001/v13/decisions",{headers:auth});
 expect((await check.json() as {allowed:boolean}).allowed).toBe(false);
});
