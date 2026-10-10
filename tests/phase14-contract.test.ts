import test from "node:test";
import assert from "node:assert/strict";
import {makeDiagnostic,classifyHttp} from "../packages/service/src/diagnostics-v14.js";
import {V13Client,V13ClientError} from "../packages/sdk/src/v13.js";

const origin="http://127.0.0.1:3001";
const client=(fetcher:typeof fetch,maxRetries:0|1|2=0)=>new V13Client({
 baseUrl:origin,accessToken:()=>"ci-synthetic-token",fetcher,maxRetries,timeoutMs:1000
});
const ok=()=>new Response(JSON.stringify({schemaVersion:"api-family-commercial-v13",
 hostAuthority:"HOST_AUTHORITY_NOT_CONFIGURED",scanningAuthority:false,meterDefinitions:[]}),
 {status:200,headers:{"content-type":"application/json"}});

test("Phase14 diagnostics are exact allowlists without secret/error/body serialization",()=>{
 const secret="super-private-token";
 const record=makeDiagnostic(Object.assign({
  kind:"HTTP_REJECTED" as const,classification:"AUTH" as const,
  statusCode:401,requestId:"poison\\u001b[31m"+secret,
  durationMs:Number.POSITIVE_INFINITY,queueWaitMs:-5,attempt:999999
 },{authorization:"Bearer "+secret,error:{message:secret},body:{secret}}));
 const wire=JSON.stringify(record);
 assert(!wire.includes(secret)&&!wire.includes("authorization")&&!wire.includes("body"));
 assert.equal(record.requestId,null);
 assert.equal(record.durationMs,null);
 assert.equal(record.queueWaitMs,null);
 assert.equal(record.attempt,100);
 assert.equal(classifyHttp(429),"CAPACITY");
 assert.equal(classifyHttp(403),"AUTH");
 assert.equal(classifyHttp(502),"INTERNAL");
});

test("Phase14 SDK fails closed for malformed base, response types and schema mismatch",async()=>{
 for(const url of ["bad url","http://127.0.0.1:3001/hidden","http://evil.test","https://alice:pw@example.com"]){
  assert.throws(()=>new V13Client({baseUrl:url,accessToken:()=>""}),/INVALID_API_ORIGIN/);
 }
 const badType=client((async()=>new Response("<html>credential</html>",{status:200,
  headers:{"content-type":"text/html"}})) as typeof fetch);
 await assert.rejects(()=>badType.capabilities(),(e:unknown)=>e instanceof V13ClientError&&e.code==="INVALID_CONTENT_TYPE");
 const badSchema=client((async()=>new Response(JSON.stringify({schemaVersion:"host-production",scanningAuthority:true}),
  {status:200})) as typeof fetch);
 await assert.rejects(()=>badSchema.capabilities(),(e:unknown)=>e instanceof V13ClientError&&e.code==="SCHEMA_VERSION_MISMATCH");
 const hostileError=client((async()=>new Response(JSON.stringify({error:"Bearer superprivate\\r\\nSECRET"}),
  {status:403})) as typeof fetch);
 await assert.rejects(()=>hostileError.capabilities(),(e:unknown)=>e instanceof V13ClientError&&e.code==="API_ERROR"&&!e.message.includes("superprivate"));
});

test("Phase14 SDK bounds streams and never exposes raw network or credential provider errors",async()=>{
 const large=client((async()=>new Response("A".repeat(1048577),{status:200})) as typeof fetch);
 await assert.rejects(()=>large.capabilities(),(e:unknown)=>e instanceof V13ClientError&&e.code==="RESPONSE_SIZE_LIMIT");
 const keyError=new V13Client({baseUrl:origin,accessToken:()=>{throw Error("secret-password");}});
 await assert.rejects(()=>keyError.summary(),(e:unknown)=>e instanceof V13ClientError&&e.code==="AUTH_PROVIDER_FAILED"&&!e.message.includes("password"));
 const badLen=client((async()=>new Response("{}",{headers:{"content-length":"1048577"}})) as typeof fetch);
 await assert.rejects(()=>badLen.summary(),(e:unknown)=>e instanceof V13ClientError&&e.code==="RESPONSE_SIZE_LIMIT");
});

test("Phase14 SDK opt-in GET retry is bounded and abort short-circuits without repeating",async()=>{
 let attempts=0;
 const retried=client((async()=>{attempts++;return attempts===1?
  new Response(JSON.stringify({error:"TEMPORARY"}),{status:503}):ok();}) as typeof fetch,1);
 assert.equal((await retried.capabilities()).scanningAuthority,false);
 assert.equal(attempts,2);
 attempts=0;
 const rejected=client((async()=>{attempts++;return new Response(JSON.stringify({error:"OVERLOADED"}),{status:503});}) as typeof fetch,2);
 await assert.rejects(()=>rejected.summary(),(e:unknown)=>e instanceof V13ClientError&&e.status===503&&e.code==="OVERLOADED");
 assert.equal(attempts,3);
 const aborted=new AbortController();aborted.abort();
 attempts=0;
 await assert.rejects(()=>client((async()=>{attempts++;return ok();}) as typeof fetch).capabilities(aborted.signal),
  (e:unknown)=>e instanceof V13ClientError&&e.code==="ABORTED");
 assert.equal(attempts,0);
});
