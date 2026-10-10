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
 await page.getByLabel("Synthetic development token (never a production login)").fill("local-test-token-beta");
 await expect(section).toHaveCount(0);
});
