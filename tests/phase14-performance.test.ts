/** Offline engineering microbenchmarks. Runner samples are not production SLOs. */
import test from "node:test";
import assert from "node:assert/strict";
import {performance} from "node:perf_hooks";
import {parseSpec,assess} from "../packages/assessment-engine/src/index.js";
import {importOfflineIsolated} from "../packages/discovery/src/isolated.js";

function stats(samples:number[]){
 const ordered=[...samples].sort((a,b)=>a-b);
 return {iterations:ordered.length,medianMs:Number(ordered[Math.floor((ordered.length-1)/2)]!.toFixed(3)),
  p95Ms:Number(ordered[Math.ceil(0.95*ordered.length)-1]!.toFixed(3)),
  minMs:Number(ordered[0]!.toFixed(3)),maxMs:Number(ordered[ordered.length-1]!.toFixed(3))};
}
const fixture=JSON.stringify({openapi:"3.0.3",info:{title:"Phase14 bounded synthetic",version:"1.0.0"},
 paths:Object.fromEntries(Array.from({length:120},(_,i)=>["/offline/test-"+i,
  {get:{operationId:"synthetic"+i,responses:{"200":{description:"fixture"}}}}]))});
test("Phase14 repeatable fixed 120-operation offline parsing and assessment benchmark",()=>{
 for(let i=0;i<5;i++)assess(parseSpec(fixture));
 const samples:number[]=[];
 const memoryBefore=process.memoryUsage().heapUsed;
 for(let i=0;i<30;i++){
  const start=performance.now();const spec=parseSpec(fixture);
  const findings=assess(spec);
  assert.equal(spec.operations.length,120);
  assert.equal(findings.length,120);
  samples.push(performance.now()-start);
 }
 const result={workload:"offline-spec120-parse-and-assess",environment:"github-hosted-node22",
  warmup:5,concurrency:1,fixtureBytes:Buffer.byteLength(fixture),
  ...stats(samples),errors:0,heapDeltaBytes:process.memoryUsage().heapUsed-memoryBefore};
 assert(Number.isFinite(result.p95Ms)&&result.p95Ms>=0);
 console.log("PHASE14_ENGINEERING_BENCHMARK "+JSON.stringify(result));
});
test("Phase14 isolated import concurrency is bounded and overload is typed",async()=>{
 const tasks=Array.from({length:8},()=>importOfflineIsolated(fixture));
 const results=await Promise.allSettled(tasks);
 const accepted=results.filter(x=>x.status==="fulfilled");
 const rejected=results.filter(x=>x.status==="rejected");
 assert.equal(accepted.length,4);
 assert.equal(rejected.length,4);
 for(const result of rejected)if(result.status==="rejected")
  assert.match(String(result.reason),/IMPORT_CONCURRENCY_LIMIT/);
 console.log("PHASE14_SYNTHETIC_LOAD "+JSON.stringify({
  submitted:8,admitted:accepted.length,rejected:rejected.length,
  concurrencyCeiling:4,customerNetworkRequests:0}));
});
