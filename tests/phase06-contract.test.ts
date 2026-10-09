import {test} from "node:test";
import {blockedMainHostPtAdapterV1,HOST_PT_CONTRACT_VERSION,PT_ENGINE_CONTRACT_VERSION} from "../packages/pt/src/contracts-v1.js";
import assert from "node:assert/strict";
import {createHmac} from "node:crypto";
import {digest,enforcePermit,issueTestPermit,verifyTestPermit,verifyStoredTestPermit,validateTestAuthority,PT_ISSUER,PT_AUDIENCE,PT_PROFILE,type PtClaims} from "../packages/pt/src/permit.js";
import {fixtureOperation,evaluateFixture} from "../packages/pt/src/fixture.js";
const key="PHASE06_TEST_ONLY_6d61f35cadbdf4f668a12c8c9e51c1f52c4e42f2d2bb";
const admin="PHASE06_SEPARATE_TEST_AUTHORITY_aa99bb88cc77dd66ee55ff44gg33";
process.env.NODE_ENV="test";
process.env.PT_TEST_AUTHORITY_ENABLED="true";
process.env.PT_TEST_SIGNING_KEY=key;
process.env.PT_TEST_AUTHORITY_KEY=admin;
const uuid=(x:string)=>x+"0000000-0000-4000-8000-000000000000";
const now=Date.now();
const claimInput={
 permitId:uuid("a"),tenantId:uuid("b"),targetId:uuid("c"),environment:"SYNTHETIC" as const,
 fixtureId:"billing-safe-v1" as const,specificationId:uuid("d"),specificationVersion:1,
 specFingerprint:"1".repeat(64),targetVerificationVersion:1,targetScopeRevision:0,scopeId:uuid("e"),
 operationKeys:["GET /status"],methods:["GET","HEAD"] as ("GET"|"HEAD")[],
 exclusions:[],maxEvaluations:3,maxConcurrency:1,ratePerMinute:5,deadlineMs:15000,
 notBefore:now-1000,expiresAt:now+60000
};
const context={tenantId:claimInput.tenantId,targetId:claimInput.targetId,scopeId:claimInput.scopeId,
 specificationId:claimInput.specificationId, specFingerprint:claimInput.specFingerprint,
 specificationVersion:1,targetVerificationVersion:1,targetScopeRevision:0,fixtureId:"billing-safe-v1",
 operationKey:"GET /status",method:"GET",path:"/status"};
function signModified(mut:(c:PtClaims)=>PtClaims,secret=key){
 const c=mut(verifyTestPermit(issueTestPermit(claimInput)));
 const body=Buffer.from(JSON.stringify(c)).toString("base64url");
 const signature=createHmac("sha256",secret).update("pt6v1."+body).digest("base64url");
 return "pt6v1."+body+"."+signature;
}
test("Phase06 valid synthetic permit is cryptographically authenticated and tenant/scope bound",()=>{
 const token=issueTestPermit(claimInput);
 const c=verifyTestPermit(token);
 assert.equal(c.issuer,PT_ISSUER);assert.equal(c.audience,PT_AUDIENCE);
 assert.equal(c.profile,PT_PROFILE);assert.equal(c.permitId,claimInput.permitId);
 assert.equal(enforcePermit(c,context),undefined);
 assert.match(digest(token),/^[a-f0-9]{64}$/);
});
for(const [name,mut,code] of [
 ["wrong issuer",(c:PtClaims)=>({...c,issuer:"production-host"}),"PERMIT_ISSUER_DENIED"],
 ["wrong audience",(c:PtClaims)=>({...c,audience:"customer-network"}),"PERMIT_AUDIENCE_DENIED"],
 ["wrong fixture",(c:PtClaims)=>({...c,fixtureId:"host" as "billing-safe-v1"}),"PERMIT_AUDIENCE_DENIED"],
 ["wrong environment",(c:PtClaims)=>({...c,environment:"PRODUCTION" as "SYNTHETIC"}),"PERMIT_AUDIENCE_DENIED"],
 ["unknown version",(c:PtClaims)=>({...c,v:2 as 1}),"PERMIT_ISSUER_DENIED"],
 ["expired",(c:PtClaims)=>({...c,expiresAt:now-1}),"PERMIT_EXPIRED_OR_NOT_YET_VALID"],
 ["future",(c:PtClaims)=>({...c,notBefore:now+100000}),"PERMIT_EXPIRED_OR_NOT_YET_VALID"],
 ["forbidden POST",(c:PtClaims)=>({...c,methods:["POST" as "GET"]}),"PERMIT_CLAIMS_INVALID"],
 ["oversized budget",(c:PtClaims)=>({...c,maxEvaluations:400}),"PERMIT_CLAIMS_INVALID"],
 ["oversized concurrency",(c:PtClaims)=>({...c,maxConcurrency:10}),"PERMIT_CLAIMS_INVALID"]
] as const){
 test("Phase06 crypto reject "+name,()=>assert.throws(()=>verifyTestPermit(signModified(mut)),{code}));
}
test("Phase06 rejects tampered payload, signature, truncated signature and unknown algorithm",()=>{
 const tok=issueTestPermit(claimInput),p=tok.split(".");
 const corrupt=p[1]!.slice(0,-1)+(p[1]!.endsWith("A")?"B":"A");
 assert.throws(()=>verifyTestPermit(["pt6v1",corrupt,p[2]].join(".")));
 assert.throws(()=>verifyTestPermit(["pt6v1",p[1],p[2]!.slice(2)+"xx"].join(".")));
 assert.throws(()=>verifyTestPermit(["pt6v1",p[1],"AAAA"].join(".")),{code:"PERMIT_SIGNATURE_LENGTH"});
 assert.throws(()=>verifyTestPermit(["HS256",p[1],p[2]].join(".")),{code:"PERMIT_ALGORITHM_DENIED"});
 assert.throws(()=>verifyTestPermit(["pt6v1",p[1]+"=",p[2]].join(".")),{code:"NONCANONICAL_PERMIT"});
 assert.throws(()=>verifyTestPermit(signModified(c=>c,"different-test-key-"+"x".repeat(64))),{code:"PERMIT_SIGNATURE_INVALID"});
});
test("Phase06 enforces target, tenant, spec, method, exclusion, revision and operation at execution boundary",()=>{
 const c=verifyTestPermit(issueTestPermit(claimInput));
 const variants:[string,Record<string,unknown>,string][]=[
  ["tenant",{tenantId:uuid("f")},"PERMIT_TENANT_MISMATCH"],
  ["target",{targetId:uuid("f")},"PERMIT_TARGET_MISMATCH"],
  ["scope",{scopeId:uuid("f")},"PERMIT_SCOPE_MISMATCH"],
  ["spec",{specificationId:uuid("f")},"PERMIT_SPECIFICATION_MISMATCH"],
  ["fingerprint",{specFingerprint:"a".repeat(64)},"PERMIT_SPECIFICATION_MISMATCH"],
  ["revision",{targetScopeRevision:4},"PERMIT_TARGET_REVISION_STALE"],
  ["fixture",{fixtureId:"external"},"PERMIT_FIXTURE_MISMATCH"],
  ["operation",{operationKey:"POST /status"},"OPERATION_OUT_OF_SCOPE"],
  ["method",{method:"POST"},"METHOD_DENIED"]
 ];
 for(const [name,change,code] of variants)
  assert.throws(()=>enforcePermit(c,{...context,...change}),{code},name);
 assert.throws(()=>enforcePermit({...c,exclusions:["/status"]},context),{code:"PATH_EXCLUDED"});
});
test("Phase06 authority gate cannot be controlled by browser headers or production config",()=>{
 assert.doesNotThrow(()=>validateTestAuthority(admin));
 assert.throws(()=>validateTestAuthority("browser-supplied-role-admin"),{code:"TEST_AUTHORITY_REQUIRED"});
 assert.throws(()=>validateTestAuthority(undefined),{code:"TEST_AUTHORITY_REQUIRED"});
 const env=process.env.NODE_ENV;
 process.env.NODE_ENV="production";
 try{
  assert.throws(()=>issueTestPermit(claimInput),{code:"PRODUCTION_SYNTHETIC_AUTHORIZATION_BLOCKED"});
  assert.throws(()=>verifyTestPermit(issueTestPermitFailover()),{code:"PRODUCTION_SYNTHETIC_AUTHORIZATION_BLOCKED"});
 }finally{process.env.NODE_ENV=env;}
});
function issueTestPermitFailover(){return "pt6v1.eyJ4IjoxfQ.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";}
test("Phase06 in-process fixture executes real GET/HEAD and never accepts unsafe paths",async()=>{
 assert.equal(fixtureOperation("GET","/status"),true);
 assert.equal(fixtureOperation("HEAD","/bills"),true);
 for(const method of ["OPTIONS","POST","PUT","PATCH","DELETE","TRACE","CONNECT"])
  assert.equal(fixtureOperation(method,"/status"),false);
 assert.equal(fixtureOperation("GET","//evil.test"),false);
 const get=await evaluateFixture({operationKey:"GET /status",method:"GET",path:"/status"});
 assert.equal(get.httpStatus,200);assert.ok(get.responseBytes>0);assert.match(get.responseHash,/^[a-f0-9]{64}$/);
 const head=await evaluateFixture({operationKey:"HEAD /status",method:"HEAD",path:"/status"});
 assert.equal(head.httpStatus,200);assert.equal(head.responseBytes,0);
 await assert.rejects(()=>evaluateFixture({operationKey:"BAD",method:"POST" as "GET",path:"/status"}));
});

test("Phase06 real Main Platform Host remains deliberately unavailable and fail-closed",async()=>{
 assert.equal(blockedMainHostPtAdapterV1.contractVersion,HOST_PT_CONTRACT_VERSION);
 assert.equal(PT_ENGINE_CONTRACT_VERSION,"synthetic-pt-governor-v1");
 await assert.rejects(()=>blockedMainHostPtAdapterV1.requestAuthorization({targetId:claimInput.targetId,specificationId:claimInput.specificationId,scopeFingerprint:claimInput.specFingerprint}),{code:"REAL_MAIN_HOST_CONTRACT_NOT_FROZEN"});
 await assert.rejects(()=>blockedMainHostPtAdapterV1.verifyAtOperation("test-permit","GET /status","GET"),{code:"REAL_MAIN_HOST_CONTRACT_NOT_FROZEN"});
 await assert.rejects(()=>blockedMainHostPtAdapterV1.revokePermit("test-permit","revoked"),{code:"REAL_MAIN_HOST_CONTRACT_NOT_FROZEN"});
});

test("Phase06 persisted claims are MAC-bound to ephemeral synthetic key",()=>{
 const bearer=issueTestPermit(claimInput),claims=verifyTestPermit(bearer),fingerprint=digest(bearer);
 assert.deepEqual(verifyStoredTestPermit(claims,fingerprint),claims);
 assert.throws(()=>verifyStoredTestPermit({...claims,maxEvaluations:20},fingerprint),{code:"PERMIT_INTEGRITY_MISMATCH"});
 assert.throws(()=>verifyStoredTestPermit(claims,"0".repeat(64)),{code:"PERMIT_INTEGRITY_MISMATCH"});
});
