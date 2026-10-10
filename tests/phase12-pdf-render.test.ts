import {test} from "node:test";
import assert from "node:assert/strict";
import {mkdtempSync,writeFileSync,rmSync} from "node:fs";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {execFileSync} from "node:child_process";
import {randomUUID} from "node:crypto";
import {planFingerprint} from "../packages/pt/src/detection.js";
import {presentVaptReport} from "../packages/service/src/phase12.js";
import {renderPhase12Pdf} from "../packages/service/src/phase12-pdf.js";
const assessmentId=randomUUID(),targetId=randomUUID(),specificationId=randomUUID();
function fixture(findings:number){
 return {schemaVersion:"autonomous-api-vapt-report-v1",assessmentId,status:"COMPLETED",
  mode:"GOVERNED_SYNTHETIC",syntheticOnly:true,customerRuntimeVerified:false,verifiedFixed:false,
  customerNetworkRequests:0,targetId,specificationId,specificationVersion:1,
  specFingerprint:"a".repeat(64),engineVersion:"autonomous-api-vapt-v1",
  coverage:{importedOperations:12,offlineOperations:12,ptRulesSelected:8,ptRulesExecuted:8,
   ptEvaluationsPlanned:14,ptEvaluationsExecuted:14,ptNotTested:false},
  findings:Array.from({length:findings},(_,i)=>({key:String(i).padStart(64,"0"),
   source:"SYNTHETIC_PT",ruleId:"PT-CASE-"+i,category:"AUTH",impact:"MEDIUM",
   confidence:"HIGH",operationKey:"GET /café/長いパス/"+i+"/"+("nested/".repeat(10)),
   explanation:"Observed synthetic condition "+i+" "+"Unicode café विश्लेषण 中文 ".repeat(4),
   remediation:"Enforce server-side checks. "+"Never disclose fixture tokens. ".repeat(7),
   evidenceFingerprint:String(i).padStart(64,"b")})),
  limitations:["Only synthetic tests, not confirmed customer vulnerabilities","NO EVIDENCE != SAFE"]};
}
function extract(pdf:Buffer):{info:string;text:string}{
 const dir=mkdtempSync(join(tmpdir(),"phase12-pdf-")),file=join(dir,"report.pdf");
 try{
  writeFileSync(file,pdf);
  const info=execFileSync("pdfinfo",[file],{encoding:"utf8",timeout:15000});
  const text=execFileSync("pdftotext",["-layout",file,"-"],{encoding:"utf8",timeout:15000});
  return {info,text};
 }finally{rmSync(dir,{recursive:true,force:true});}
}
test("Phase12 actual PDF: independent Poppler parser sees source identity, branded title and disclaimers",async()=>{
 const source=fixture(0);
 const report=presentVaptReport(source,{id:randomUUID(),assessmentId,
  fingerprint:planFingerprint(source),createdAt:"2026-10-10T10:00:00.000Z"});
 const bytes=await renderPhase12Pdf(report,{displayName:"Independent Test Organization",
  reportTitle:"Authorized Synthetic Evidence",accentHex:"#123ABC",version:1});
 assert.equal(bytes.subarray(0,5).toString(),"%PDF-");
 const {info,text}=extract(bytes);
 assert.match(info,/Pages:\s*[1-9]/);
 assert(text.includes(assessmentId));
 assert(text.includes(report.sourceFingerprint));
 assert.match(text,/Authorized Synthetic Evidence/);
 assert.match(text,/No findings were observed/);
 assert.match(text,/NO EVIDENCE != SAFE/);
 assert.match(text,/NO LONGER OBSERVED != VERIFIED_FIXED/);
 assert(!text.includes("VERIFIED_FIXED: true"));
});
test("Phase12 actual PDF: long Unicode findings flow to multiple parseable pages",async()=>{
 const source=fixture(27);
 const report=presentVaptReport(source,{id:randomUUID(),assessmentId,
  fingerprint:planFingerprint(source),createdAt:"2026-10-10T10:00:00.000Z"});
 const pdf=await renderPhase12Pdf(report);
 const {info,text}=extract(pdf);
 const pages=Number(info.match(/Pages:\s*(\d+)/)?.[1]??0);
 assert(pages>=3&&pages<60,"Expected bounded multi-page layout, got "+pages);
 assert(text.includes("PT-CASE-0"));
 assert(text.includes("PT-CASE-26"));
 assert(text.includes("synthetic"));
 assert(!text.includes("Bearer raw-secret"));
 assert(!text.includes("password=real"));
});
