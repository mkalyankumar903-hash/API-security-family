/** GitHub-hosted isolated PDF real Chromium OS child fault qualification. */
import {randomUUID} from "node:crypto";
import {planFingerprint} from "../../packages/pt/src/detection.js";
import {presentVaptReport} from "../../packages/service/src/phase12.js";
import {renderPhase12Pdf} from "../../packages/service/src/phase12-pdf.js";
if(process.env.NODE_ENV!=="test"||process.env.SYNTHETIC_AUTH_ENABLED!=="true"||
 process.env.GITHUB_ACTIONS!=="true"||!process.send)throw Error("GH_CHILD_ONLY");
const id=randomUUID();
const source={schemaVersion:"autonomous-api-vapt-report-v1",assessmentId:id,status:"COMPLETED",
 mode:"GOVERNED_SYNTHETIC",syntheticOnly:true,customerRuntimeVerified:false,verifiedFixed:false,
 customerNetworkRequests:0,targetId:randomUUID(),specificationId:randomUUID(),specificationVersion:1,
 specFingerprint:"a".repeat(64),engineVersion:"autonomous-api-vapt-v1",
 coverage:{importedOperations:12,offlineOperations:12,ptRulesSelected:8,ptRulesExecuted:8,
  ptEvaluationsPlanned:14,ptEvaluationsExecuted:14,ptNotTested:false},
 findings:[],limitations:["Synthetic offline ONLY","UNKNOWN is not SAFE"]};
const report=presentVaptReport(source,{id:randomUUID(),assessmentId:id,
 fingerprint:planFingerprint(source),createdAt:"2026-10-10T10:00:00.000Z"});
const original=report.sourceFingerprint;
try{
 let failedCode="";
 try{await renderPhase12Pdf(report);}catch(error){
  failedCode=error instanceof Error?error.message:"UNKNOWN";
 }
 const expected=process.env.PHASE14_PDF_CHILD_FAULT==="render-timeout"?
  "PDF_RENDER_TIMEOUT":"PDF_RENDERER_UNAVAILABLE_OR_TIMED_OUT";
 if(failedCode!==expected)throw Error("FAULT_MUST_REJECT_PARTIAL_PDF_"+failedCode);
 if(report.sourceFingerprint!==original)throw Error("IMMUTABLE_REPORT_MUTATED");
 delete process.env.PHASE14_PDF_CHILD_FAULT;
 const good=await renderPhase12Pdf(report);
 if(good.subarray(0,5).toString()!=="%PDF-")throw Error("RECOVERY_PDF_INVALID");
 if(report.sourceFingerprint!==original)throw Error("RECOVERY_FINGERPRINT_CHANGED");
 process.send({kind:"PHASE14_PDF_CHILD_DONE",failedCode,bytes:good.length,immutability:true});
}catch(e){
 process.send({kind:"PHASE14_PDF_CHILD_ERROR",code:e instanceof Error?e.message:"UNKNOWN"});
 process.exitCode=1;
}
