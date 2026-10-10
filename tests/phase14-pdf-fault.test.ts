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

test("Phase14 actual Chromium OS child death before page and during PDF render, plus bounded real timeout",async()=>{
 const {spawn}=await import("node:child_process");
 for(const mode of ["before-page","mid-render","render-timeout"] as const){
  const child=spawn(process.execPath,["--import","tsx","tests/helpers/phase14-pdf-subprocess.ts"],{
   env:{...process.env,NODE_ENV:"test",SYNTHETIC_AUTH_ENABLED:"true",GITHUB_ACTIONS:"true",
    PHASE14_PDF_CHILD_FAULT:mode},
   stdio:["ignore","pipe","pipe","ipc"]
  });
  let transcript="",renderStarted=false,killedBrowser=false,success=false;
  child.stderr?.on("data",(x:Buffer)=>{transcript+=x.toString().slice(0,1000);});
  try{
   const completed=new Promise<{code:number|null;signal:NodeJS.Signals|null}>((resolve,reject)=>{
    const timeout=setTimeout(()=>{child.kill("SIGKILL");reject(Error("PHASE14_REAL_RENDER_FAULT_TIMEOUT_"+mode));},16000);
    child.on("message",(raw:unknown)=>{
     const m=raw as {kind?:string;chromiumPid?:number;failedCode?:string;immutability?:boolean;bytes?:number;code?:string};
     if(m.kind==="PHASE14_BROWSER_LAUNCHED"||m.kind==="PHASE14_RENDER_IN_FLIGHT"){
      renderStarted=true;
      if(!Number.isSafeInteger(m.chromiumPid)||!m.chromiumPid||m.chromiumPid<=1||
       m.chromiumPid===child.pid){reject(Error("PHASE14_INVALID_CHROMIUM_OS_PID"));return;}
      try{process.kill(m.chromiumPid,"SIGKILL");killedBrowser=true;child.send({kind:"PHASE14_CONTINUE"});}
      catch(e){reject(e);}
     }
     if(m.kind==="PHASE14_PDF_CHILD_DONE"){
      assert.equal(m.immutability,true);
      assert(m.bytes&&m.bytes>1000);
      assert.equal(m.failedCode,mode==="render-timeout"?"PDF_RENDER_TIMEOUT":"PDF_RENDERER_UNAVAILABLE_OR_TIMED_OUT");
      success=true;
     }
     if(m.kind==="PHASE14_PDF_CHILD_ERROR")reject(Error("PDF_CHILD_"+m.code));
    });
    child.once("exit",(code,signal)=>{clearTimeout(timeout);resolve({code,signal});});
    child.once("error",reject);
   });
   const exit=await completed;
   assert.deepEqual(exit,{code:0,signal:null},"child must verify no partial PDF and recover "+mode+" "+transcript.slice(-250));
   assert(success,"real rendered recovery observed");
   if(mode!=="render-timeout"){assert(renderStarted);assert(killedBrowser,"OS process SIGKILL required");}
  }finally{if(child.exitCode===null)child.kill("SIGKILL");}
 }
});
