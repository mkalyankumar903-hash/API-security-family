import test from "node:test";
import assert from "node:assert/strict";
import {randomUUID} from "node:crypto";
import {planFingerprint} from "../packages/pt/src/detection.js";
import {presentVaptReport} from "../packages/service/src/phase12.js";
const id=randomUUID(),target=randomUUID(),spec=randomUUID();
const report={schemaVersion:"autonomous-api-vapt-report-v1",status:"COMPLETED",
 assessmentId:id,mode:"OFFLINE_ONLY",syntheticOnly:true,customerRuntimeVerified:false,
 verifiedFixed:false,customerNetworkRequests:0,targetId:target,specificationId:spec,
 specificationVersion:1,engineVersion:"autonomous-api-vapt-v1",specFingerprint:"a".repeat(64),
 fixtureVersion:null,fullAuthorizedVaptCompleted:false,
 coverage:{importedOperations:2,offlineOperations:2,ptRulesSelected:0,ptRulesExecuted:0,
 ptEvaluationsPlanned:0,ptEvaluationsExecuted:0,ptNotTested:true},
 findings:[{key:"b".repeat(64),source:"SPEC_ONLY",ruleId:"API-01",impact:"LOW",
  explanation:"Bearer abc123",remediation:"Set password=abc123",evidenceFingerprint:"c".repeat(64)}],
 limitations:["NO EVIDENCE != SAFE"]};
const metadata={id:randomUUID(),assessmentId:id,fingerprint:planFingerprint(report),
 createdAt:"2026-10-10T01:00:00.000Z"};
test("Phase12 presentation derives only immutable report counts, retaining synthetic boundaries",()=>{
 const p=presentVaptReport(report,metadata);
 assert.equal(p.summary.findingCount,1);
 assert.equal(p.coverage.importedOperations,2);
 assert.equal(p.verifiedFixed,false);
 assert.equal(p.customerRuntimeVerified,false);
 assert.equal(p.schemaVersion,"api-security-report-presentation-v1");
 assert.match(p.disclaimer,/No customer runtime vulnerability/);
 assert(!JSON.stringify(p).includes("abc123"));
});
test("Phase12 refuses forged source fingerprint or mutable runtime verdict",()=>{
 assert.throws(()=>presentVaptReport(report,{...metadata,fingerprint:"a".repeat(64)}),/IMMUTABLE_SOURCE_REPORT_INTEGRITY_INVALID/);
 assert.throws(()=>presentVaptReport({...report,verifiedFixed:true},metadata),/IMMUTABLE_SOURCE_REPORT_INTEGRITY_INVALID/);
 assert.throws(()=>presentVaptReport({...report,customerRuntimeVerified:true},metadata),/IMMUTABLE_SOURCE_REPORT_INTEGRITY_INVALID/);
 assert.throws(()=>presentVaptReport({...report,assessmentId:randomUUID()},metadata),/IMMUTABLE_SOURCE_REPORT_INTEGRITY_INVALID/);
});
test("Phase12 rejects oversized and malformed immutable report content",()=>{
 const huge={...report,findings:Array.from({length:1001},()=>report.findings[0])};
 assert.throws(()=>presentVaptReport(huge,{...metadata,fingerprint:planFingerprint(huge)}),/REPORT_PRESENTATION_LIMIT/);
 assert.throws(()=>presentVaptReport({},metadata),/IMMUTABLE_SOURCE_REPORT_INTEGRITY_INVALID/);
});
