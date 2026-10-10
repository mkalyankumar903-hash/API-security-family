import test from "node:test";
import assert from "node:assert/strict";
import {randomUUID,randomBytes,createHmac} from "node:crypto";
import {validateEvent,verifySyntheticEvent,verifyRotatedSyntheticEvent,verifySyntheticExternalSnapshot,unit,V13,hostNotConfigured} from "../packages/contracts/src/commercial-v13.js";
import {V13Client,V13ClientError} from "../packages/sdk/src/v13.js";
const e=()=>({schemaVersion:V13,eventId:randomUUID(),tenantId:randomUUID(),
 issuer:"lumicsec-ci-synthetic-v13",audience:"api-family-v13-test",issuedAt:new Date().toISOString(),
 expiresAt:new Date(Date.now()+120000).toISOString(),entitlementId:randomUUID(),
 revision:1,feature:"IMMUTABLE_REPORT_OBSERVED",limit:2,status:"ISSUED"});
test("Phase13 strict contract rejects forged, stale, versioned, hostile or overflowing entitlements",()=>{
 const v=e();assert.equal(validateEvent(v).limit,2);
 for(const bad of [{...v,audience:"wrong"},{...v,feature:"PT_NETWORK_EXECUTION"},
  {...v,limit:-1},{...v,limit:1.5},{...v,limit:Number.MAX_SAFE_INTEGER+1},
  {...v,schemaVersion:"v14"},{...v,critical:"ignore"}, {...v,tenantId:"not-uuid"},
  {...v,expiresAt:new Date(Date.now()-1000).toISOString()}])
  assert.throws(()=>validateEvent(bad));
 for(const bad of [-1,0.5,Number.POSITIVE_INFINITY,Number.MAX_SAFE_INTEGER+1])
  assert.throws(()=>unit(bad));
 assert.throws(()=>hostNotConfigured(),/HOST_AUTHORITY_NOT_CONFIGURED/);
});
test("Phase13 HMAC signs exact bytes with independent CI key, rejects tampering/replay window",()=>{
 const key=randomBytes(48),raw=Buffer.from(JSON.stringify(e()));
 const signature=createHmac("sha256",key).update(raw).digest("hex");
 const oldNode=process.env.NODE_ENV,oldFlag=process.env.SYNTHETIC_AUTH_ENABLED;
 process.env.NODE_ENV="test";process.env.SYNTHETIC_AUTH_ENABLED="true";
 try{
  assert.equal(verifySyntheticEvent(raw,signature,key).schemaVersion,V13);
  assert.throws(()=>verifySyntheticEvent(Buffer.from(raw.toString().replace("ISSUED","REVOKED")),signature,key),/INVALID_EVENT_SIGNATURE/);
  assert.throws(()=>verifySyntheticEvent(raw,"0".repeat(64),key),/INVALID_EVENT_SIGNATURE/);
  assert.throws(()=>verifySyntheticEvent(raw,signature,randomBytes(48)),/INVALID_EVENT_SIGNATURE/);
  assert.throws(()=>verifySyntheticEvent(raw,signature,key,Date.now()+360000),/EVENT_EXPIRED_OR_SKEWED/);
  assert.throws(()=>verifySyntheticEvent(Buffer.alloc(4097),signature,key),/INVALID_EVENT_SIGNATURE/);
  process.env.NODE_ENV="production";
  assert.throws(()=>verifySyntheticEvent(raw,signature,key),/HOST_AUTHORITY_NOT_CONFIGURED/);
 }finally{if(oldNode===undefined)delete process.env.NODE_ENV;else process.env.NODE_ENV=oldNode;
  if(oldFlag===undefined)delete process.env.SYNTHETIC_AUTH_ENABLED;else process.env.SYNTHETIC_AUTH_ENABLED=oldFlag;}
});
test("Phase13 SDK injects auth at request time, validates origin, never creates Host credentials",async()=>{
 const paths:string[]=[],auth:string[]=[];
 const sdk=new V13Client({baseUrl:"http://127.0.0.1:3001",accessToken:async()=>"safe-test-bearer",
  fetcher:(async(input,init)=>{paths.push(String(input));auth.push(String(new Headers(init?.headers).get("authorization")));
   return new Response(JSON.stringify({schemaVersion:V13,hostAuthority:"HOST_AUTHORITY_NOT_CONFIGURED",meterDefinitions:[],scanningAuthority:false}),{status:200,headers:{"content-type":"application/json"}});}) as typeof fetch});
 assert.equal((await sdk.capabilities()).scanningAuthority,false);
 assert(paths[0]?.endsWith("/v13/capabilities"));assert.equal(auth[0],"Bearer safe-test-bearer");
 assert.throws(()=>new V13Client({baseUrl:"http://example.com",accessToken:()=>""}),/INVALID_API_ORIGIN/);
 await assert.rejects(()=>new V13Client({baseUrl:"http://localhost",accessToken:()=>"",
  fetcher:(async()=>new Response(JSON.stringify({error:"PERMISSION_DENIED"}),{status:403})) as typeof fetch}).summary(),
  (error:unknown)=>error instanceof V13ClientError&&error.code==="MISSING_AUTHENTICATION");
 assert.throws(()=>sdk.decision(-1),/INVALID_QUANTITY/);
});

test("Phase13 key rotation rejects wrong key id or expired trust window",()=>{
 const previous=process.env.NODE_ENV,flag=process.env.SYNTHETIC_AUTH_ENABLED;
 process.env.NODE_ENV="test";process.env.SYNTHETIC_AUTH_ENABLED="true";
 const key=randomBytes(48),raw=Buffer.from(JSON.stringify(e()));
 const sig=createHmac("sha256",key).update(raw).digest("hex");
 try{
  const now=Date.now(),keys=[{keyId:"2026-key",key,validFrom:now-60000,validUntil:now+60000}];
  assert.equal(verifyRotatedSyntheticEvent(raw,sig,"2026-key",keys,now).schemaVersion,V13);
  assert.throws(()=>verifyRotatedSyntheticEvent(raw,sig,"wrong",keys,now),/UNTRUSTED_SIGNING_KEY/);
  assert.throws(()=>verifyRotatedSyntheticEvent(raw,sig,"2026-key",keys,now+120000),/UNTRUSTED_SIGNING_KEY/);
  assert.throws(()=>verifyRotatedSyntheticEvent(raw,sig,"2026-key",
   [{...keys[0]!,key:randomBytes(48)}],now),/INVALID_EVENT_SIGNATURE/);
 }finally{if(previous===undefined)delete process.env.NODE_ENV;else process.env.NODE_ENV=previous;
 if(flag===undefined)delete process.env.SYNTHETIC_AUTH_ENABLED;else process.env.SYNTHETIC_AUTH_ENABLED=flag;}
});
test("Phase13 external snapshot independent signature validation is mandatory",()=>{
 const prev=process.env.NODE_ENV,flag=process.env.SYNTHETIC_AUTH_ENABLED;
 process.env.NODE_ENV="test";process.env.SYNTHETIC_AUTH_ENABLED="true";
 const key=randomBytes(48),now=new Date();
 const snapshot={schemaVersion:V13,snapshotId:randomUUID(),tenantId:randomUUID(),
  issuer:"lumicsec-ci-external-accounting-v13",audience:"api-family-reconcile-v13-test",
  feature:"IMMUTABLE_REPORT_OBSERVED",meterVersion:1,
  monthStart:now.toISOString().slice(0,7)+"-01",watermarkAt:now.toISOString(),
  observedUnits:0,revision:1,issuedAt:now.toISOString(),expiresAt:new Date(now.getTime()+120000).toISOString()};
 const raw=Buffer.from(JSON.stringify(snapshot)),sig=createHmac("sha256",key).update(raw).digest("hex");
 try{
  assert.equal(verifySyntheticExternalSnapshot(raw,sig,key).observedUnits,0);
  assert.throws(()=>verifySyntheticExternalSnapshot(raw,"0".repeat(64),key),/INVALID_SNAPSHOT_SIGNATURE/);
  assert.throws(()=>verifySyntheticExternalSnapshot(Buffer.from(JSON.stringify({...snapshot,meterVersion:2})),
   createHmac("sha256",key).update(JSON.stringify({...snapshot,meterVersion:2})).digest("hex"),key),/UNSUPPORTED_CONTRACT/);
 }finally{if(prev===undefined)delete process.env.NODE_ENV;else process.env.NODE_ENV=prev;
 if(flag===undefined)delete process.env.SYNTHETIC_AUTH_ENABLED;else process.env.SYNTHETIC_AUTH_ENABLED=flag;}
});
