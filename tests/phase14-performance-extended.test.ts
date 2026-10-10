/** Deterministic implementation-backed offline microbenchmarks; not production SLOs. */
import test from "node:test";
import assert from "node:assert/strict";
import {performance} from "node:perf_hooks";
import {importOfflineDocument,compareInventory} from "../packages/discovery/src/index.js";
import {detectInventory} from "../packages/assessment-engine/src/inventory.js";
import {V13Client} from "../packages/sdk/src/v13.js";
function summary(name:string,bytes:number,warmup:number,samples:number[],memoryBefore:number){
 const sorted=[...samples].sort((a,b)=>a-b),p95=sorted[Math.ceil(sorted.length*0.95)-1]!;
 const out={workload:name,fixtureBytes:bytes,warmup,iterations:samples.length,concurrency:1,
  medianMs:Number(sorted[Math.floor((sorted.length-1)/2)]!.toFixed(3)),
  p95Ms:Number(p95.toFixed(3)),minMs:Number(sorted[0]!.toFixed(3)),
  maxMs:Number(sorted.at(-1)!.toFixed(3)),errors:0,
  heapDeltaBytes:process.memoryUsage().heapUsed-memoryBefore,
  environment:"GitHub-hosted Node22 synthetic/no customer network",strictP95Budget:null};
 assert(Number.isFinite(out.p95Ms)&&out.p95Ms>=0);
 console.log("PHASE14_EXTENDED_BENCHMARK "+JSON.stringify(out));
}
const base={openapi:"3.1.0",info:{title:"Phase14 extended",version:"1.0.0"},
 paths:Object.fromEntries(Array.from({length:80},(_,i)=>["/safe/"+i,{
  get:{operationId:"synthetic"+i,responses:{"200":{description:"Synthetic"}}}}]))};
const fixture=JSON.stringify(base);
const altered=JSON.stringify({...base,paths:{...base.paths,
 "/safe/new":{get:{operationId:"newSynthetic",responses:{"200":{description:"Synthetic"}}}}}});
test("Phase14 imported API inventory and deterministic detection measured through actual source",async()=>{
 const warmup=3,iterations=12;
 for(let i=0;i<warmup;i++){const a=await importOfflineDocument(fixture);detectInventory(a);}
 const memory=process.memoryUsage().heapUsed,samples:number[]=[];
 for(let i=0;i<iterations;i++){
  const started=performance.now(),inventory=await importOfflineDocument(fixture);
  const detection=detectInventory(inventory);
  assert.equal(inventory.operations.length,80);
  assert.equal(detection.engineVersion,"inventory-v1");
  samples.push(performance.now()-started);
 }
 summary("offline-import-and-detect-80-operations",Buffer.byteLength(fixture),warmup,samples,memory);
});
test("Phase14 structural inventory diff measured with two real parser outputs",async()=>{
 const a=await importOfflineDocument(fixture),b=await importOfflineDocument(altered);
 const warmup=5,iterations=30,samples:number[]=[];
 for(let i=0;i<warmup;i++)compareInventory(a,b);
 const memory=process.memoryUsage().heapUsed;
 for(let i=0;i<iterations;i++){
  const started=performance.now(),diff=compareInventory(a,b);
  assert.equal(diff.added.length,1);
  assert.equal(diff.removed.length,0);
  assert.equal(diff.reviewRequired,true);
  samples.push(performance.now()-started);
 }
 summary("structural-inventory-diff-80-to-81",Buffer.byteLength(fixture)+Buffer.byteLength(altered),warmup,samples,memory);
});
test("Phase14 actual SDK v13 GET transport baseline and Host-denied response",async()=>{
 const url="http://127.0.0.1:3001";let calls=0;
 const client=new V13Client({baseUrl:url,accessToken:()=>"synthetic",fetcher:(async()=>{
  calls++;
  return new Response(JSON.stringify({schemaVersion:"api-family-commercial-v13",
   hostAuthority:"HOST_AUTHORITY_NOT_CONFIGURED",scanningAuthority:false,meterDefinitions:[]}),
   {status:200,headers:{"content-type":"application/json"}});
 }) as typeof fetch,timeoutMs:2000});
 const warmup=5,iterations=30,samples:number[]=[];
 for(let i=0;i<warmup;i++)assert.equal((await client.capabilities()).scanningAuthority,false);
 const memory=process.memoryUsage().heapUsed;
 for(let i=0;i<iterations;i++){
  const start=performance.now();
  assert.equal((await client.capabilities()).scanningAuthority,false);
  samples.push(performance.now()-start);
 }
 assert.equal(calls,warmup+iterations);
 summary("sdk-read-only-fetch-serialization",100,warmup,samples,memory);
});
