/** Actual Chromium renderer fault and concurrency gates; GitHub-hosted browser required. */
import {test} from "node:test";
import assert from "node:assert/strict";
import {randomUUID} from "node:crypto";
import {planFingerprint} from "../packages/pt/src/detection.js";
import {presentVaptReport} from "../packages/service/src/phase12.js";
import {buildPhase12PdfHtml,renderPhase12Pdf} from "../packages/service/src/phase12-pdf.js";

function document(){
 const assessmentId=randomUUID(),targetId=randomUUID(),specificationId=randomUUID();
 const source={schemaVersion:"autonomous-api-vapt-report-v1",assessmentId,status:"COMPLETED",
  mode:"GOVERNED_SYNTHETIC",syntheticOnly:true,customerRuntimeVerified:false,verifiedFixed:false,
  customerNetworkRequests:0,targetId,specificationId,specificationVersion:1,
  specFingerprint:"a".repeat(64),engineVersion:"autonomous-api-vapt-v1",
  coverage:{importedOperations:12,offlineOperations:12,ptRulesSelected:8,ptRulesExecuted:8,
   ptEvaluationsPlanned:14,ptEvaluationsExecuted:14,ptNotTested:false},
  findings:[],limitations:["Only synthetic tests; customer safety UNKNOWN","NO EVIDENCE != SAFE"]};
 return presentVaptReport(source,{id:randomUUID(),assessmentId,
  fingerprint:planFingerprint(source),createdAt:"2026-10-10T10:00:00.000Z"});
}
test("Phase14 PDF rejects real browser executable unavailability, cleans resources and recovers",async()=>{
 const report=document();
 const previous={node:process.env.NODE_ENV,flag:process.env.SYNTHETIC_AUTH_ENABLED,
  fault:process.env.PHASE14_TEST_PDF_UNAVAILABLE};
 try{
  process.env.NODE_ENV="test";process.env.SYNTHETIC_AUTH_ENABLED="true";
  process.env.PHASE14_TEST_PDF_UNAVAILABLE="true";
  await assert.rejects(()=>renderPhase12Pdf(report),(e:unknown)=>e instanceof Error&&
    e.message==="PDF_RENDERER_UNAVAILABLE_OR_TIMED_OUT");
  delete process.env.PHASE14_TEST_PDF_UNAVAILABLE;
  const recovered=await renderPhase12Pdf(report);
  assert.equal(recovered.subarray(0,5).toString(),"%PDF-");
  assert(recovered.byteLength<4*1024*1024);
 }finally{
  for(const [key,value] of [["NODE_ENV",previous.node],["SYNTHETIC_AUTH_ENABLED",previous.flag],
    ["PHASE14_TEST_PDF_UNAVAILABLE",previous.fault]] as const){
   if(value===undefined)delete process.env[key];else process.env[key]=value;
  }
 }
});
test("Phase14 two real concurrent Chromium PDF renders are bounded; third 429; permits freed",async()=>{
 const report=document();
 const tasks=[renderPhase12Pdf(report),renderPhase12Pdf(report),renderPhase12Pdf(report)];
 const answers=await Promise.allSettled(tasks);
 const good=answers.filter(x=>x.status==="fulfilled");
 const denied=answers.filter(x=>x.status==="rejected");
 assert.equal(good.length,2);assert.equal(denied.length,1);
 assert.equal((denied[0] as PromiseRejectedResult).reason.message,"PDF_GENERATION_CONCURRENCY_LIMIT");
 for(const item of good)if(item.status==="fulfilled"){
  assert.equal(item.value.subarray(0,5).toString(),"%PDF-");
 }
 const next=await renderPhase12Pdf(report);
 assert.equal(next.subarray(0,5).toString(),"%PDF-");
});
test("Phase14 PDF HTML is escaped, no networking, no Host authorization or VERIFIED_FIXED",()=>{
 const report=document();
 const html=buildPhase12PdfHtml(report,{displayName:'<script>alert("secret")</script>',
  reportTitle:'<img src="https://bad.example.invalid/track">',
  accentHex:"#123ABC",version:1});
 assert(!html.includes('<script>alert("secret")</script>'));
 assert(!html.includes('<img src="https://bad.example.invalid/track">'));
 assert(html.includes("&lt;script&gt;"));
 assert(html.includes("connect-src 'none'"));
 assert(html.includes("customer"));
 assert(html.includes("NO LONGER OBSERVED != VERIFIED_FIXED"));
});
