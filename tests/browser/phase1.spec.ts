import {test,expect} from "@playwright/test";
import {drainQueue} from "../../packages/worker/src/index.js";
import {withTenant,closeDatabase} from "../../packages/database/src/index.js";
const token="local-test-token-alpha";
const tenant="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const api="http://127.0.0.1:3001";
test.afterAll(async()=>{await closeDatabase();});
test("real Chromium registration → scope → signed test challenge → invalidation → assessment → suspension / foreign-tenant denial",async({page,request})=>{
 const suffix=crypto.randomUUID().slice(0,8);
 await page.goto("/");
 await page.getByPlaceholder("Payments API").fill("Phase1 UI "+suffix);
 await page.getByPlaceholder("https://api.example.invalid").fill("https://browser-"+suffix+".fixture.invalid");
 await page.getByRole("button",{name:"Register target"}).click();
 const selector=page.getByLabel("Select target");
 await expect(selector).not.toHaveValue("");
 const targetId=await selector.inputValue();
 await expect(page.getByRole("heading",{name:"Secure target onboarding · Phase 1"})).toBeVisible();
 await expect(page.getByText(/Ownership:.*PENDING HOST VERIFICATION/)).toBeVisible();
 await page.getByLabel("Scope paths").fill("/\n/v1/*");
 await page.getByLabel("Path exclusions").fill("/admin");
 await page.getByLabel("Proposed methods").fill("GET,HEAD");
 await page.getByLabel("Proposed request budget").fill("0");
 await page.getByRole("button",{name:"Save scope proposal"}).click();
 await expect(page.getByText("Scope history: 1 revision(s).")).toBeVisible();
 await page.getByRole("button",{name:"Issue verification challenge"}).click();
 await expect(page.getByLabel("Issued challenge")).not.toHaveValue("");
 await page.getByRole("button",{name:"Generate synthetic TEST proof"}).click();
 await expect(page.getByLabel("Signed test attestation")).not.toHaveValue("");
 const proof=await page.getByLabel("Signed test attestation").inputValue();
 const challengeId=await page.getByLabel("Issued challenge").inputValue();
 const invalid=await request.post(api+"/v1/targets/"+targetId+"/verification/evidence",{
  headers:{authorization:"Bearer "+token},
  data:{challengeId,evidenceType:"SIGNED_SYNTHETIC_ATTESTATION",attestation:proof.slice(0,-2)+"aa"}
 });
 expect(invalid.status()).toBe(403);
 await page.getByRole("button",{name:"Submit signed test verification"}).click();
 await expect(page.getByText(/Ownership:.*SYNTHETIC VERIFIED TEST ONLY/)).toBeVisible();
 const decisions=await request.get(api+"/v1/targets/"+targetId+"/verification/decisions",{headers:{authorization:"Bearer "+token}});
 expect((await decisions.json()).length).toBe(1);
 const replay=await request.post(api+"/v1/targets/"+targetId+"/verification/evidence",{
  headers:{authorization:"Bearer "+token},data:{challengeId,evidenceType:"SIGNED_SYNTHETIC_ATTESTATION",attestation:proof}
 });
 expect(replay.status()).toBe(409);
 await page.getByLabel("Target display name").fill("Updated Phase1 "+suffix);
 await page.getByLabel("Canonical target URL").fill("https://changed-"+suffix+".fixture.invalid");
 await page.getByRole("button",{name:"Save target revision"}).click();
 await expect(page.getByText(/Ownership:.*PENDING HOST VERIFICATION/)).toBeVisible();
 await page.getByRole("button",{name:"Issue verification challenge"}).click();
 await page.getByLabel("Unverified customer evidence").fill("I own the DNS zone");
 await page.getByRole("button",{name:"Submit claim without verification"}).click();
 await expect(page.getByText(/Untrusted customer claim recorded/)).toBeVisible();
 await expect(page.getByText(/Ownership:.*PENDING HOST VERIFICATION/)).toBeVisible();
 await page.getByLabel("Credential profile reference").fill("credref:browserfixture000123");
 await page.getByRole("button",{name:"Store unverified reference"}).click();
 await expect(page.getByText(/credref:browserfixture000123/)).toBeVisible();
 await page.getByLabel("Specification file").setInputFiles("fixtures/insecure.openapi.json");
 await expect(page.getByText("/admin/accounts")).toBeVisible();
 await page.getByRole("button",{name:"Start SPEC_ONLY assessment"}).click();
 await expect(page.getByRole("status").filter({hasText:"Assessment status:"})).toContainText("QUEUED");
 expect(await drainQueue()).toBe(1);
 await expect(page.getByRole("heading",{name:"4. Evidence-backed report"})).toBeVisible();
 const foreign=await request.get(api+"/v1/targets/"+targetId,{headers:{authorization:"Bearer local-test-token-beta"}});
 expect(foreign.status()).toBe(404);
 await page.getByRole("button",{name:"Suspend target"}).click();
 await expect(page.getByText(/Lifecycle:.*SUSPENDED/)).toBeVisible();
 await expect(page.getByRole("button",{name:"Start SPEC_ONLY assessment"})).toBeDisabled();
 const specs=await request.get(api+"/v1/targets/"+targetId+"/specifications",{headers:{authorization:"Bearer "+token}});
 const ids=await specs.json();
 const denied=await request.post(api+"/v1/targets/"+targetId+"/assessments",{
  headers:{authorization:"Bearer "+token,"idempotency-key":"suspended-"+crypto.randomUUID()},
  data:{specificationId:ids[0].id,mode:"SPEC_ONLY"}
 });
 expect(denied.status()).toBe(409);
 await page.getByRole("button",{name:"View target audit history"}).click();
 await expect(page.getByText("VERIFICATION_SYNTHETIC_ACCEPTED")).toBeVisible();
});
test("real browser expiry and unauthorized request fail closed",async({page,request})=>{
 const suffix=crypto.randomUUID().slice(0,8);
 await page.goto("/");
 await page.getByPlaceholder("Payments API").fill("Expiry "+suffix);
 await page.getByPlaceholder("https://api.example.invalid").fill("https://expiry-"+suffix+".fixture.invalid");
 await page.getByRole("button",{name:"Register target"}).click();
 await expect(page.getByLabel("Select target")).not.toHaveValue("");
 const id=await page.getByLabel("Select target").inputValue();
 await expect(page.getByRole("heading",{name:"Secure target onboarding · Phase 1"})).toBeVisible();
 await page.getByRole("button",{name:"Issue verification challenge"}).click();
 await expect(page.getByLabel("Issued challenge")).not.toHaveValue("");
 const challenge=await page.getByLabel("Issued challenge").inputValue();
 await page.getByLabel("Unverified customer evidence").fill("Untrusted evidence");
 await withTenant(tenant,async tx=>tx.query("UPDATE api_target_challenges SET expires_at=now()-interval '1 minute' WHERE id=$1",[challenge]));
 await page.getByRole("button",{name:"Submit claim without verification"}).click();
 await expect(page.getByText(/Untrusted customer claim recorded: EXPIRED/)).toBeVisible();
 const reuse=await request.post(api+"/v1/targets/"+id+"/verification/evidence",{
  headers:{authorization:"Bearer "+token},data:{challengeId:challenge,evidenceType:"CUSTOMER_CLAIM",attestation:"again"}
 });
 expect(reuse.status()).toBe(409);
 await page.getByLabel("Synthetic development token (never a production login)").fill("forged-unauthorized-token");
 await expect(page.getByRole("alert")).toContainText("Access denied: PERMISSION_DENIED");
});
