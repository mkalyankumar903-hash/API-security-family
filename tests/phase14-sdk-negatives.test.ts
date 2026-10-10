import {test} from "node:test";
import assert from "node:assert/strict";
import {V13Client,V13ClientError} from "../packages/sdk/src/v13.js";
const origin="http://127.0.0.1:3001";
function client(fetcher:typeof fetch,timeoutMs=100,maxRetries:0|1|2=0){
 return new V13Client({baseUrl:origin,accessToken:()=>Promise.resolve("test-token"),fetcher,timeoutMs,maxRetries});
}
async function rejects(p:Promise<unknown>,code:string){
 await assert.rejects(p,(error:unknown)=>error instanceof V13ClientError&&error.code===code);
}
test("Phase14 SDK timeout bounds hung credential provider, not just network calls",async()=>{
 const sdk=new V13Client({baseUrl:origin,accessToken:()=>new Promise<string>(()=>{}),
  timeoutMs:100,fetcher:(async()=>{throw Error("should not fetch");}) as typeof fetch});
 await rejects(sdk.capabilities(),"TRANSPORT_OR_TIMEOUT");
});
test("Phase14 SDK caller abort interrupts hung credential provider",async()=>{
 const a=new AbortController();
 const sdk=new V13Client({baseUrl:origin,accessToken:()=>new Promise<string>(()=>{}),
  timeoutMs:1000,fetcher:(async()=>{throw Error("must not fetch");}) as typeof fetch});
 const work=sdk.capabilities(a.signal);
 a.abort();
 await rejects(work,"ABORTED");
});
test("Phase14 SDK bounds streaming response when custom fetch ignores signal",async()=>{
 const sdk=client((async()=>new Response(new ReadableStream({
  start(controller){controller.enqueue(new Uint8Array([123]));},
  pull(){return new Promise<void>(()=>{});}
 }),{status:200,headers:{"content-type":"application/json"}})) as typeof fetch);
 await rejects(sdk.summary(),"TRANSPORT_OR_TIMEOUT");
});
test("Phase14 SDK hostile response: wrong media, incomplete JSON, huge body, secret-safe error",async()=>{
 const invalid=client((async()=>new Response("{\"x\":1}",{headers:{"content-type":"text/plain"}})) as typeof fetch);
 await rejects(invalid.summary(),"INVALID_CONTENT_TYPE");
 const truncated=client((async()=>new Response("{\"x\":",{headers:{"content-type":"application/json"}})) as typeof fetch);
 await rejects(truncated.summary(),"INVALID_RESPONSE");
 const huge=client((async()=>new Response("x".repeat(1048578),{headers:{"content-type":"application/json"}})) as typeof fetch);
 await rejects(huge.summary(),"RESPONSE_SIZE_LIMIT");
 const secret=client((async()=>new Response(JSON.stringify({error:"SECRET_TOKEN_12345"}),{status:403})) as typeof fetch);
 await rejects(secret.summary(),"API_ERROR");
});
test("Phase14 SDK never retries 401,403,404,409,500, rejects unsafe base origins",async()=>{
 for(const code of [401,403,404,409,500]){
  let calls=0;
  const sdk=client((async()=>{calls++;return new Response(JSON.stringify({error:"DENIED"}),{status:code});}) as typeof fetch,1000,2);
  await assert.rejects(sdk.summary(),(e:unknown)=>e instanceof V13ClientError&&e.status===code);
  assert.equal(calls,1,"do not amplify non-retryable status "+code);
 }
 for(const bad of ["http://localhost.evil.test","http://127.0.0.1@bad.invalid",
  "http://127.0.0.1:3001/path","ftp://127.0.0.1","https://u:p@example.com",
  "http://127.0.0.1:3001?evil=1"]){
  assert.throws(()=>new V13Client({baseUrl:bad,accessToken:()=>""}),/INVALID_API_ORIGIN/);
 }
});
test("Phase14 SDK abort cancels retry backoff before making another request",async()=>{
 const ctrl=new AbortController();let hits=0;
 const sdk=client((async()=>{
  hits++;if(hits===1){queueMicrotask(()=>ctrl.abort());}
  return new Response(JSON.stringify({error:"CAPACITY"}),{status:429});
 }) as typeof fetch,1000,2);
 await rejects(sdk.summary(ctrl.signal),"ABORTED");
 assert.equal(hits,1);
});
test("Phase14 SDK correct successful JSON envelope still remains Host-disabled",async()=>{
 const sdk=client((async()=>new Response(JSON.stringify({schemaVersion:"api-family-commercial-v13",
  hostAuthority:"HOST_AUTHORITY_NOT_CONFIGURED",scanningAuthority:false,meterDefinitions:[]}),
  {headers:{"content-type":"application/json;charset=utf-8"}})) as typeof fetch);
 assert.equal((await sdk.capabilities()).scanningAuthority,false);
 assert.throws(()=>sdk.usage(0),/INVALID_PAGINATION/);
 assert.throws(()=>sdk.usage(25,100001),/INVALID_PAGINATION/);
 assert.throws(()=>sdk.decision(-1),/INVALID_QUANTITY/);
});
