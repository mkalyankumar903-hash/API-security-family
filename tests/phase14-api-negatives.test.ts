import {test} from "node:test";
import assert from "node:assert/strict";
import {makeApp} from "../packages/service/src/app.js";

test("Phase14 real Fastify rejects unsafe URL, content-types, invalid pagination, headers and request credentials",async()=>{
 const previous={node:process.env.NODE_ENV,synthetic:process.env.SYNTHETIC_AUTH_ENABLED,tokens:process.env.DEV_TOKENS_JSON};
 process.env.NODE_ENV="test";process.env.SYNTHETIC_AUTH_ENABLED="true";
 process.env.DEV_TOKENS_JSON=JSON.stringify({"synthetic-local-token":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"});
 const app=await makeApp();
 const auth={authorization:"Bearer synthetic-local-token"};
 try{
  const urls=["http://example.invalid","https://localhost","https://127.0.0.1/",
    "https://user:password@example.invalid","https://example.invalid/a/%2e%2e/b",
    "https://example.invalid:4444","https://example.invalid/a?token=secret",
    "https://example.invalid/#secret","https://example.invalid//ambiguous"];
  for(const url of urls){
   const result=await app.inject({method:"POST",url:"/v1/targets",headers:auth,
    payload:{name:"Bad target",environment:"SYNTHETIC",baseUrl:url}});
   assert.equal(result.statusCode,400,url+" "+result.body);
   assert.equal(result.headers["cache-control"],"no-store");
   assert.equal(result.headers["x-content-type-options"],"nosniff");
   assert(!result.body.includes("password")&&!result.body.includes("token=secret"));
  }
  const xml=await app.inject({method:"POST",url:"/v1/targets",headers:{
   ...auth,"content-type":"application/xml"},payload:"<target/>"});
  assert.equal(xml.statusCode,415,xml.body);
  assert.equal(xml.json().error,"UNSUPPORTED_CONTENT_TYPE");
  assert.equal(xml.headers["cache-control"],"no-store");
  const invalidJson=await app.inject({method:"POST",url:"/v1/targets",headers:{
   ...auth,"content-type":"application/json"},payload:"{\"not-json\":"});
  assert.equal(invalidJson.statusCode,400);
  const missing=await app.inject({method:"GET",url:"/v1/targets",headers:{"x-tenant-id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}});
  assert.equal(missing.statusCode,401);
  const spoofed=await app.inject({method:"GET",url:"/v1/targets",headers:{
   authorization:"Bearer wrong-tenant-token","x-tenant-id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}});
  assert.equal(spoofed.statusCode,403);
  const badId=await app.inject({method:"GET",url:"/v1/targets/not-a-uuid",headers:auth});
  assert.equal(badId.statusCode,400);
  for(const query of ["?limit=0","?limit=101","?offset=-1","?limit=Infinity"]){
   const response=await app.inject({method:"GET",url:"/v1/targets"+query,headers:auth});
   assert.equal(response.statusCode,400,query+" "+response.body);
  }
  const key=await app.inject({method:"POST",url:"/v1/targets",headers:{...auth,
   "idempotency-key":"bad!"},payload:{name:"Valid name",environment:"SYNTHETIC",
   baseUrl:"https://safe-"+Date.now()+".fixture.invalid"}});
  assert.equal(key.statusCode,400);
  const origin=await app.inject({method:"OPTIONS",url:"/v1/targets",headers:{
   origin:"https://evil.example.invalid","access-control-request-method":"POST",
   "access-control-request-headers":"authorization,content-type"}});
  assert.notEqual(origin.headers["access-control-allow-origin"],"https://evil.example.invalid");
 }finally{
  await app.close();
  for(const [key,value] of [["NODE_ENV",previous.node],["SYNTHETIC_AUTH_ENABLED",previous.synthetic],
   ["DEV_TOKENS_JSON",previous.tokens]] as const){
   if(value===undefined)delete process.env[key];else process.env[key]=value;
  }
 }
});
