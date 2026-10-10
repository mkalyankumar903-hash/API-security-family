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
