import {test} from "node:test";
import assert from "node:assert/strict";
import {canonicalTargetUrl,checkScope,checkCredentialReference,signSynthetic,verifySynthetic,checkName,checkEnvironment} from "../packages/targets/src/contracts.js";
const origin="https://api.fixture.invalid";
test("URL accepts normalized public-style HTTPS DNS only, no network DNS lookups",()=>{
 for(const [input,expected] of [
  ["https://api.fixture.invalid/",origin],
  ["https://API.FIXTURE.INVALID/v1",origin+"/v1"],
  ["https://api.fixture.invalid:443",origin],
  ["https://api.fixture.invalid:8443",origin+":8443"]
 ])assert.equal(canonicalTargetUrl(input).canonicalUrl,expected,input);
});
test("URL parser rejects internal/IP/SSRF, ambiguous encodings, canonicalization and unsafe identifiers",()=>{
 for(const bad of [
  "http://api.fixture.invalid","https://localhost","https://intranet.internal",
  "https://router.local","https://127.0.0.1","https://169.254.169.254","https://[::1]",
  "https://api.fixture.invalid@127.0.0.1","https://api.fixture.invalid?x=1",
  "https://api.fixture.invalid#section","https://api.fixture.invalid:22",
  "https://api.fixture.invalid:invalid","https://api..fixture.invalid",
  "https://api.fixture.invalid./","https://api.fixture.invalid/path%2fadmin",
  "https://api.fixture.invalid/a%5cb","https://api.fixture.invalid/%2e%2e/",
  "https://api.fixture.invalid/x/../admin","https://api.fixture.invalid/x//y",
  "https://api.fixture.invalid\\@evil.invalid","https://bücher.invalid",
  "https://-bad.invalid","https://api.fixture.invalid/a b","https://api.fixture.invalid/x\n"
 ])assert.throws(()=>canonicalTargetUrl(bad),/UNSAFE|INVALID|PORT|AMBIGUOUS/,bad);
});
test("strict proposed scope is not approved authority; rejects origin drift and unsafe paths",()=>{
 const good={origins:[origin],paths:["/","/v1/*"],exclusions:["/admin"],methods:["GET","HEAD","POST"],operations:["GET /v1/users"],maxRequests:100000,windowStart:null,windowEnd:null};
 assert.deepEqual(checkScope(good,origin).authority,"CUSTOMER_PROPOSED");
 for(const bad of [
  {...good,origins:["https://other.invalid"]},{...good,maxRequests:100001},
  {...good,methods:["TRACE"]},{...good,paths:["/v1/../admin"]},
  {...good,paths:["//double"]},{...good,exclusions:["/../etc"]},
  {...good,operations:["DELETE ../../admin"]},{...good,windowStart:"2026-10-10T00:00:00Z",windowEnd:"2026-10-09T00:00:00Z"}
 ])assert.throws(()=>checkScope(bad,origin));
});
test("opaque references cannot carry bearer/secret/credential values",()=>{
 assert.equal(checkCredentialReference("credref:syntheticprofile01"),"credref:syntheticprofile01");
 for(const raw of ["Bearer aaa", "sk_live_KJHS32","password=abc","credref:abc","credref:foo/bar","credref:token=leak"]){
  assert.throws(()=>checkCredentialReference(raw));
 }
 assert.throws(()=>checkName(" padded "));
 assert.throws(()=>checkEnvironment("TRUSTED"));
});
test("synthetic signed attestation cryptography, tampering, wrong signing root, expiry and production fail closed",()=>{
 const oldFlag=process.env.SYNTHETIC_VERIFICATION_ENABLED,oldSecret=process.env.PHASE1_SYNTHETIC_SIGNING_KEY,oldMode=process.env.NODE_ENV;
 try{
  process.env.NODE_ENV="test";process.env.SYNTHETIC_VERIFICATION_ENABLED="true";
  process.env.PHASE1_SYNTHETIC_SIGNING_KEY="phase01_known_isolated_signing_root_33_chars_only_tests";
  const claims={v:1 as const,tenant:"tenant-a",target:"target-a",challenge:"challenge-a",origin,environment:"SYNTHETIC",
   revision:2,verificationVersion:3,nonceHash:"a".repeat(64),expiresAt:new Date(Date.now()+900000).toISOString()};
  const signed=signSynthetic(claims);
  assert.deepEqual(verifySynthetic(signed),claims);
  // Flip a decoded HMAC byte rather than a Base64URL character (which may alias
  // the same bytes because SHA-256 has 2 unused pad bits in its final sextet).
  const [payload,signature]=signed.split(".");
  assert.ok(payload && signature);
  const modified=Buffer.from(signature,"base64url");
  modified[0]! ^= 0x01;
  const changedSignature=modified.toString("base64url");
  assert.notDeepEqual(modified,Buffer.from(signature,"base64url"));
  assert.throws(()=>verifySynthetic(payload+"."+changedSignature),/ATTESTATION_SIGNATURE_INVALID/);
  // A signature with different text but identical decoded HMAC must be rejected.
  const alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  const finalIndex=alphabet.indexOf(signature.at(-1)!);
  assert.ok(finalIndex>=0);
  const noncanonical=signature.slice(0,-1)+alphabet[finalIndex ^ 1]!;
  assert.notEqual(noncanonical,signature);
  assert.deepEqual(Buffer.from(noncanonical,"base64url"),Buffer.from(signature,"base64url"));
  assert.throws(()=>verifySynthetic(payload+"."+noncanonical),/ATTESTATION_SIGNATURE_INVALID/);
  // Payload changes must fail with the original, unmodified signature.
  const changedPayload=Buffer.from(payload,"base64url");
  changedPayload[0]! ^= 0x01;
  assert.throws(()=>verifySynthetic(changedPayload.toString("base64url")+"."+signature),/ATTESTATION_SIGNATURE_INVALID/);
  assert.throws(()=>verifySynthetic(payload+"."+signature.slice(1)),/ATTESTATION_SIGNATURE_INVALID/);
  process.env.PHASE1_SYNTHETIC_SIGNING_KEY="different_isolated_secret_root_that_cannot_verify";
  assert.throws(()=>verifySynthetic(signed));
  process.env.PHASE1_SYNTHETIC_SIGNING_KEY="phase01_known_isolated_signing_root_33_chars_only_tests";
  const expired=signSynthetic({...claims,expiresAt:"2020-01-01T00:00:00Z"});
  assert.throws(()=>verifySynthetic(expired),/EXPIRED/);
  process.env.NODE_ENV="production";
  assert.throws(()=>signSynthetic(claims),/DISABLED/);
 }finally{
  if(oldFlag===undefined)delete process.env.SYNTHETIC_VERIFICATION_ENABLED;else process.env.SYNTHETIC_VERIFICATION_ENABLED=oldFlag;
  if(oldSecret===undefined)delete process.env.PHASE1_SYNTHETIC_SIGNING_KEY;else process.env.PHASE1_SYNTHETIC_SIGNING_KEY=oldSecret;
  if(oldMode===undefined)delete process.env.NODE_ENV;else process.env.NODE_ENV=oldMode;
 }
});
