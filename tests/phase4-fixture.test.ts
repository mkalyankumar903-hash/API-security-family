import {test} from "node:test";
import assert from "node:assert/strict";
import {evaluateAuthFixture,SCHEMES,policyFor,declaredSchemeCoverage} from "../packages/assessment-engine/src/auth-fixture.js";
const tenant="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",target="aaaaaaaa-bbbb-4aaa-8aaa-aaaaaaaaaaaa";
for(const scheme of SCHEMES){
 test("Phase04 actual Fastify.inject "+scheme+" secure and deliberately broken auth state matrix",async()=>{
  const secure=await evaluateAuthFixture({scheme,fixture:"secure-v1",tenantId:tenant,targetId:target});
  assert.equal(secure.coverage.attempted,21);
  assert.equal(secure.coverage.deviations,0);
  assert.equal(secure.coverage.unknown,0);
  assert.equal(secure.coverage.passed,21);
  assert.equal(secure.customerNetworkRequests,0);
  for(const rule of ["AUTH04_MISSING_CREDENTIAL","AUTH04_INVALID_CREDENTIAL","AUTH04_EXPIRED",
    "AUTH04_REVOKED","AUTH04_WRONG_ISSUER","AUTH04_WRONG_AUDIENCE","AUTH04_TAMPERED",
    "AUTH04_ROTATED_OLD","AUTH04_LOGOUT_INVALIDATION"]){
   const e=secure.evaluations.find(x=>x.ruleId===rule);
   assert.equal(e?.observed,"DENY",rule);
   assert.equal(e?.result,"PASS",rule);
  }
  assert.equal(secure.evaluations.find(x=>x.ruleId==="AUTH04_OWN_A")?.observed,"ALLOW");
  assert.equal(secure.evaluations.find(x=>x.ruleId==="AUTH04_CROSS_USER_BOLA")?.observed,"DENY");
  assert.equal(secure.evaluations.find(x=>x.ruleId==="AUTH04_ADMIN_RESTRICTED")?.observed,"DENY");
  const broken=await evaluateAuthFixture({scheme,fixture:"broken-bola-v1",tenantId:tenant,targetId:target});
  assert.equal(broken.coverage.deviations,1);
  assert.equal(broken.evaluations.filter(x=>x.result==="DEVIATION")[0]?.ruleId,"AUTH04_CROSS_USER_BOLA");
  assert.equal(broken.evaluations.filter(x=>x.result==="DEVIATION")[0]?.observed,"ALLOW");
  assert.deepEqual(secure.evaluations.map(x=>x.fingerprint),
   (await evaluateAuthFixture({scheme,fixture:"secure-v1",tenantId:tenant,targetId:target})).evaluations.map(x=>x.fingerprint));
  assert.ok(!JSON.stringify(broken).includes("Authorization"));
  assert.equal(broken.runtimeValidation,false);
 });
}
test("Phase04 policy, unsupported declarations and arbitrary fixture input fail closed",async()=>{
 assert.equal(policyFor("user-a","FIXTURE_RECORD_B"),"DENY");
 assert.equal(policyFor("admin","FIXTURE_RECORD_B"),"ALLOW");
 assert.equal(policyFor(null,"FIXTURE_ADMIN"),"DENY");
 const schemes=declaredSchemeCoverage({bearer:{type:"http",scheme:"bearer"},oidc:{type:"openIdConnect"},
  cookie:{type:"apiKey",in:"cookie"},basic:{type:"http",scheme:"basic"}});
 assert.equal(schemes.filter(x=>x.status==="UNSUPPORTED").length,2);
 await assert.rejects(()=>evaluateAuthFixture({scheme:"BEARER",fixture:"https://customer.example.com" as never,tenantId:tenant,targetId:target}),/UNSUPPORTED_FIXTURE_PROFILE/);
 await assert.rejects(()=>evaluateAuthFixture({scheme:"BEARER",fixture:"secure-v1",tenantId:tenant,targetId:target,maxEvaluations:1}),/FIXTURE_EVALUATION_BOUND_EXCEEDED/);
 await assert.rejects(()=>evaluateAuthFixture({scheme:"BEARER",fixture:"secure-v1",tenantId:"forged",targetId:target}),/INVALID_FIXTURE_CONTEXT/);
});
