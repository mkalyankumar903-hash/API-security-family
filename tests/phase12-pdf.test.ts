import {test} from "node:test";
import assert from "node:assert/strict";
import {randomUUID} from "node:crypto";
import {planFingerprint} from "../packages/pt/src/detection.js";
import {presentVaptReport} from "../packages/service/src/phase12.js";
import {buildPhase12PdfHtml} from "../packages/service/src/phase12-pdf.js";
const assessmentId=randomUUID(),targetId=randomUUID(),specificationId=randomUUID();
const fixture={schemaVersion:"autonomous-api-vapt-report-v1",assessmentId,status:"COMPLETED",
 mode:"OFFLINE_ONLY",syntheticOnly:true,customerRuntimeVerified:false,verifiedFixed:false,
 customerNetworkRequests:0,targetId,specificationId,specificationVersion:1,
 specFingerprint:"a".repeat(64),engineVersion:"autonomous-api-vapt-v1",
 coverage:{importedOperations:3,offlineOperations:3,ptRulesSelected:0,ptRulesExecuted:0,
 ptEvaluationsPlanned:0,ptEvaluationsExecuted:0,ptNotTested:true},
 findings:[{key:"b".repeat(64),ruleId:"<script>alert(1)</script>",source:"SPEC_ONLY",
  explanation:"<&> Bearer test-secret-token",remediation:"Never use password=test-secret-value",
  evidenceFingerprint:"c".repeat(64),operationKey:"GET /café/長いリソース"}],
 limitations:["<img src='http://private.invalid/secret'>","Synthetic only"]};
const report=presentVaptReport(fixture,{id:randomUUID(),assessmentId,
 fingerprint:planFingerprint(fixture),createdAt:"2026-10-10T10:00:00.000Z"});
test("Phase12 HTML PDF layout retains report fingerprint, source identity and mandatory synthetic disclaimer",()=>{
 const html=buildPhase12PdfHtml(report);
 assert.match(html,/<html lang="en">/);
 assert(html.includes(report.sourceFingerprint));
 assert(html.includes(assessmentId));
 assert(html.includes("UNKNOWN != SAFE"));
 assert(html.includes("NO LONGER OBSERVED != VERIFIED_FIXED"));
 assert(html.includes("Executive overview"));
 assert(html.includes("GET /café/長いリソース"));
});
test("Phase12 PDF HTML escapes untrusted findings, does not embed script/image or leaked bearer",()=>{
 const html=buildPhase12PdfHtml(report);
 assert(!html.includes("<script>alert(1)</script>"));
 assert(!html.includes("<img src="));
 assert(!html.includes("test-secret-token"));
 assert(!html.includes("test-secret-value"));
 assert(html.includes("&lt;script&gt;"));
 assert(html.includes("img src=")); // rendered as escaped text, not an HTML image
 assert(html.includes("default-src 'none'"));
});
test("Phase12 rejects forged PDF security authority or brand injection",()=>{
 assert.throws(()=>buildPhase12PdfHtml({...report,verifiedFixed:true}),/UNTRUSTED_REPORT_PRESENTATION/);
 assert.throws(()=>buildPhase12PdfHtml(report,{displayName:"Safe",reportTitle:"<iframe>",
  accentHex:"red;url(x)",version:1}),/INVALID_BRANDING/);
});
