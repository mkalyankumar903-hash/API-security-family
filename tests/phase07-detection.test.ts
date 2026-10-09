import {test} from "node:test";
import assert from "node:assert/strict";
import {executeTrustedSynthetic,PROFILES,ACTORS,PATHS,fixtureOperationV7,type Evidence,type Profile} from "../packages/pt/src/security-fixture.js";
import {RULES,planRules,evaluateRule} from "../packages/pt/src/detection.js";
process.env.NODE_ENV="test";
process.env.PT_TEST_AUTHORITY_ENABLED="true";
const expectedPositive=new Map<string,Profile>([
 ["PT-AUTH-ANONYMOUS","MISSING_AUTH_ENFORCEMENT"],
 ["PT-AUTH-INVALID","MISSING_AUTH_ENFORCEMENT"],
 ["PT-AUTH-EXPIRED","MISSING_AUTH_ENFORCEMENT"],
 ["PT-AUTH-REVOKED","MISSING_AUTH_ENFORCEMENT"],
 ["PT-BOLA-CROSS-USER","CROSS_USER_ACCESS_WEAKNESS"],
 ["PT-FUNCTION-ROLE","ROLE_RESTRICTION_WEAKNESS"],
 ["PT-SENSITIVE-FIELD","SENSITIVE_RESPONSE_EXPOSURE"],
 ["PT-CONFIDENTIAL-CACHE","INSECURE_CACHE_POLICY"]
]);
async function evidenceFor(rule:typeof RULES[number],profile:Profile):Promise<Evidence[]>{
 const responses:Evidence[]=[];
 for(const c of rule.cases)responses.push(await executeTrustedSynthetic({
  method:c.method,path:c.path,actor:c.actor,profile
 }));
 return responses;
}
test("Phase07 immutable allowlisted fixture denies unsafe methods and untrusted paths",async()=>{
 for(const method of ["POST","PUT","PATCH","DELETE","OPTIONS","TRACE","CONNECT","BAD"])
  for(const path of PATHS)assert.equal(fixtureOperationV7(method,path),false);
 for(const path of ["https://example.invalid","//localhost","/pt/../../metadata","/pt/account?url=remote"])
  assert.equal(fixtureOperationV7("GET",path),false);
 for(const p of PATHS)assert.equal(fixtureOperationV7("HEAD",p),true);
 for(const actor of ACTORS)assert.ok(actor.length>0);
 await assert.rejects(()=>executeTrustedSynthetic({method:"POST" as "GET",path:"/pt/account",actor:"alice",profile:"SECURE_BASELINE"}));
 await assert.rejects(()=>executeTrustedSynthetic({method:"GET",path:"/pt/account",actor:"unknown" as "alice",profile:"SECURE_BASELINE"}));
 await assert.rejects(()=>executeTrustedSynthetic({method:"GET",path:"/pt/account",actor:"alice",profile:"OTHER" as Profile}));
 const current=process.env.NODE_ENV;process.env.NODE_ENV="production";
 try{await assert.rejects(()=>executeTrustedSynthetic({method:"GET",path:"/pt/account",actor:"alice",profile:"SECURE_BASELINE"}),/PRODUCTION_SYNTHETIC_DETECTION_BLOCKED/);}
 finally{process.env.NODE_ENV=current;}
});
for(const rule of RULES){
 test("Phase07 "+rule.id+" secure negative, vulnerable positive, missing evidence, stable fingerprint",async()=>{
  const secure=await evidenceFor(rule,"SECURE_BASELINE");
  const secureResult=evaluateRule(rule,"SECURE_BASELINE",secure);
  assert.equal(secureResult.status,"PASS");
  assert.equal(secureResult.fingerprint,null);
  const vulnerable=await evidenceFor(rule,expectedPositive.get(rule.id)!);
  const observed=evaluateRule(rule,expectedPositive.get(rule.id)!,vulnerable);
  assert.equal(observed.status,"OBSERVED");
  assert.match(observed.fingerprint!,/^[0-9a-f]{64}$/);
  assert.equal(observed.confidence,"HIGH");assert.equal(observed.runtimeCustomerVerification,false);
  const repeat=await evidenceFor(rule,expectedPositive.get(rule.id)!);
  assert.equal(evaluateRule(rule,expectedPositive.get(rule.id)!,repeat).fingerprint,observed.fingerprint);
  assert.equal(evaluateRule(rule,expectedPositive.get(rule.id)!,vulnerable.slice(0,-1)).status,"INCONCLUSIVE");
  assert.equal(evaluateRule(rule,"SECURE_BASELINE",vulnerable).status,"INCONCLUSIVE");
  assert.ok(vulnerable.every(x=>x.exposedPaths.every(p=>p.startsWith("$."))));
  assert.ok(vulnerable.every(x=>x.responseHash.length===64));
  assert.equal(JSON.stringify(vulnerable).includes("SYNTHETIC_PLACEHOLDER_NOT_A_SECRET"),false);
 });
}
test("Phase07 no customer verdict can replace an actually observed comparison",async()=>{
 assert.equal(planRules(RULES.map(x=>x.id)).length,RULES.length);
 assert.throws(()=>planRules(["PT-AUTH-ANONYMOUS","PT-AUTH-ANONYMOUS"]));
 assert.throws(()=>planRules(["FAKE_DETECTOR"]));
 const r=RULES[0]!,e=await evidenceFor(r,"SECURE_BASELINE");
 const fake=e.map(x=>({...x,status:200,responseHash:"bad"}));
 assert.equal(evaluateRule(r,"SECURE_BASELINE",fake).status,"INCONCLUSIVE");
});
test("Phase07 fixture profiles are bounded and deterministic",async()=>{
 assert.equal(PROFILES.length,6);
 for(const p of PROFILES){
  const a=await executeTrustedSynthetic({method:"GET",path:"/pt/confidential",actor:"alice",profile:p});
  const b=await executeTrustedSynthetic({method:"GET",path:"/pt/confidential",actor:"alice",profile:p});
  assert.equal(a.responseHash,b.responseHash);
  assert.ok(a.responseBytes<=2048);
 }
});
