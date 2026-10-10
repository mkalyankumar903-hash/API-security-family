import test from "node:test";
import assert from "node:assert/strict";
import {randomUUID,randomBytes,createHmac} from "node:crypto";
import {validateEvent,verifySyntheticEvent,unit,V13,hostNotConfigured} from "../packages/contracts/src/commercial-v13.js";
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
 assert(paths[0].endsWith("/v13/capabilities"));assert.equal(auth[0],"Bearer safe-test-bearer");
 assert.throws(()=>new V13Client({baseUrl:"http://example.com",accessToken:()=>""}),/INVALID_API_ORIGIN/);
 await assert.rejects(()=>new V13Client({baseUrl:"http://localhost",accessToken:()=>"",
  fetcher:(async()=>new Response(JSON.stringify({error:"PERMISSION_DENIED"}),{status:403})) as typeof fetch}).summary(),
  (error:unknown)=>error instanceof V13ClientError&&error.code==="MISSING_AUTHENTICATION");
 assert.throws(()=>sdk.decision(-1),/INVALID_QUANTITY/);
});
