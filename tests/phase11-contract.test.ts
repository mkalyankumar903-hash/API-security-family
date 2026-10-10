import test from "node:test";
import assert from "node:assert/strict";
import {randomUUID} from "node:crypto";
import {buildAutonomousVaptPlan,autonomousVaptFingerprint,correlateAutonomousVaptEvidence,
 AutonomousVaptError} from "../packages/pt/src/autonomous-vapt.js";
import {buildOrchestrationPlan} from "../packages/pt/src/orchestrator.js";
import {RULES} from "../packages/pt/src/detection.js";
import {DETECTION_FIXTURE} from "../packages/pt/src/security-fixture.js";

const tenantId=randomUUID(),targetId=randomUUID(),specificationId=randomUUID();
const specFingerprint="a".repeat(64),inventoryFingerprint="b".repeat(64);
const ops=[...new Map(RULES.map(r=>[r.path,{key:"GET "+r.path,method:"GET",path:r.path,authState:"DECLARED"}])).values()];
const base={tenantId,targetId,specificationId,specificationVersion:1,specFingerprint,inventoryFingerprint,
 targetVerificationVersion:1,targetScopeRevision:1,offlineEngine:"inventory-v1" as const,operations:ops};
const binding={tenantId,targetId,environment:"SYNTHETIC" as const,specificationId,
 specificationVersion:1,specFingerprint,targetVerificationVersion:1,targetScopeRevision:1,
 scopeId:randomUUID(),fixtureId:DETECTION_FIXTURE,permitId:randomUUID(),permitFingerprint:"c".repeat(64),
 operationKeys:ops.map(x=>x.key),exclusions:[],maxEvaluations:30,ratePerMinute:20,maxConcurrency:1,deadlineMs:30000};
test("Phase11 offline-only deterministic plan has no PT stages or permit",()=>{
 const a=buildAutonomousVaptPlan({...base,mode:"OFFLINE_ONLY"});
 const b=buildAutonomousVaptPlan({...base,mode:"OFFLINE_ONLY",operations:[...ops].reverse()});
 assert.equal(autonomousVaptFingerprint(a),autonomousVaptFingerprint(b));
 assert.deepEqual(a.stages.map(x=>x.id),["offline","correlation","report"]);
 assert.equal(a.plannedEvaluations,0);assert.equal(a.permitId,null);
 assert.equal(a.customerNetworkRequests,0);
});
test("Phase11 governed synthetic plan binds exact original Phase09 plan",()=>{
 const pt=buildOrchestrationPlan("SYNTHETIC_PT_COMPLETE_SUPPORTED","SECURE_BASELINE",binding,
  ops.map(x=>({operation_key:x.key,method:x.method,path:x.path})));
 const plan=buildAutonomousVaptPlan({...base,mode:"GOVERNED_SYNTHETIC",ptPlan:pt});
 assert.deepEqual(plan.stages.map(x=>x.id),["offline","governed-pt","correlation","report"]);
 assert.equal(plan.ptPolicyId,"SYNTHETIC_PT_COMPLETE_SUPPORTED");
 assert.equal(plan.rules.length,8);
 assert.equal(plan.plannedEvaluations,pt.evaluations.length);
 assert.throws(()=>buildAutonomousVaptPlan({...base,mode:"GOVERNED_SYNTHETIC",ptPlan:{
  ...pt,binding:{...pt.binding,tenantId:randomUUID()}}}),AutonomousVaptError);
});
test("Phase11 no forged authorization or executable input accepted",()=>{
 assert.throws(()=>buildAutonomousVaptPlan({...base,mode:"GOVERNED_SYNTHETIC"}),AutonomousVaptError);
 assert.throws(()=>buildAutonomousVaptPlan({...base,mode:"OFFLINE_ONLY",operations:[...ops,{key:"x",method:"EXEC",path:"/x",authState:"DECLARED"}]}),AutonomousVaptError);
 assert.throws(()=>buildAutonomousVaptPlan({...base,mode:"OFFLINE_ONLY",specFingerprint:"invalid"}),AutonomousVaptError);
});
test("Phase11 provenance-bound relationships do not promote verified customer findings",()=>{
 const ptRuleOperations={"PT-AUTH-ANONYMOUS":ops[0]!.key};
 const synthetic=[{ruleId:"PT-AUTH-ANONYMOUS",revision:"1.0.0",fingerprint:"c".repeat(64),
 code:"SYNTHETIC_OBSERVED",remediation:"Require server-side auth",impact:"MEDIUM",confidence:"HIGH"}];
 const offline=[{ruleId:"API03_AUTH_UNDECLARED",ruleRevision:"1.0.0",
  operationKey:ops[0]!.key,fingerprint:"d".repeat(64),category:"AUTH",impact:"LOW",
  confidence:"HIGH",explanation:"No declaration",remediation:"Document expected authentication"}];
 const context={tenantId,targetId,specFingerprint,fixtureId:DETECTION_FIXTURE,fixtureVersion:1,
  profile:"VULNERABLE_BASELINE",ptRuleOperations};
 const a=correlateAutonomousVaptEvidence(context,offline,synthetic);
 const b=correlateAutonomousVaptEvidence(context,offline,synthetic);
 assert.deepEqual(a,b);
 assert.equal(a.observations.length,2);
 assert(a.observations.every(o=>!o.customerVulnerabilityConfirmed&&!o.verifiedFixed));
 assert(a.relationships.every(x=>x.relationship==="RELATED_NOT_EQUIVALENT"));
 assert.throws(()=>correlateAutonomousVaptEvidence({...context,tenantId:randomUUID()},[
  {...offline[0]!,fingerprint:"bad"}],synthetic),AutonomousVaptError);
});
