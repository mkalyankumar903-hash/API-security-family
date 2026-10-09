import {test} from "node:test";
import {strict as assert} from "node:assert";
import {buildOrchestrationPlan,orchestrationFingerprint,validateOrchestrationPlan,OrchestratorPlanError,type Binding} from "../packages/pt/src/orchestrator.js";
const b:Binding={tenantId:"11111111-1111-4111-8111-111111111111",targetId:"22222222-2222-4222-8222-222222222222",
 environment:"SYNTHETIC",specificationId:"33333333-3333-4333-8333-333333333333",specificationVersion:1,
 specFingerprint:"a".repeat(64),targetVerificationVersion:1,targetScopeRevision:1,scopeId:"44444444-4444-4444-8444-444444444444",
 fixtureId:"pt-security-v1",permitId:"55555555-5555-4555-8555-555555555555",permitFingerprint:"b".repeat(64),
 operationKeys:["key-account","key-resources","key-admin","key-confidential"],exclusions:[],maxEvaluations:20,
 ratePerMinute:20,maxConcurrency:1,deadlineMs:30000};
const ops=[{operation_key:"key-account",method:"GET",path:"/pt/account"},
 {operation_key:"key-resources",method:"GET",path:"/pt/resources/bob"},
 {operation_key:"key-admin",method:"GET",path:"/pt/admin"},
 {operation_key:"key-confidential",method:"GET",path:"/pt/confidential"}];
const build=(policy="SYNTHETIC_PT_COMPLETE_SUPPORTED",binding=b,operations=ops)=>buildOrchestrationPlan(policy,"SECURE_BASELINE",binding,operations);
test("Phase09 identical immutable authority yields stable canonical plans",()=>{
 const first=build(),second=build("SYNTHETIC_PT_COMPLETE_SUPPORTED",b,[...ops].reverse());
 assert.equal(orchestrationFingerprint(first),orchestrationFingerprint(second));
 assert.equal(first.maxEvaluations,14);
 assert.deepEqual(first.stages.map(x=>x.id),["preflight","authentication","authorization","response","reconciliation","finalization"]);
 assert.equal(first.stages.reduce((n,s)=>n+s.budget,0),14);
});
test("Phase09 policy profile restricts rule and evaluation selection",()=>{
 const p=build("SYNTHETIC_PT_AUTHORIZATION_FOCUSED");
 assert.equal(p.rules.length,2);assert.equal(p.maxEvaluations,4);
 assert.deepEqual(p.stages.map(x=>x.id),["preflight","authorization","reconciliation","finalization"]);
});
test("Phase09 policy rejects invalid scope, budget and unknown profiles",()=>{
 assert.throws(()=>build("NO_SUCH_POLICY"),OrchestratorPlanError);
 assert.throws(()=>build("SYNTHETIC_PT_BASELINE",{...b,maxEvaluations:10}),/ORCHESTRATION_BUDGET_TOO_SMALL/);
 assert.throws(()=>build("SYNTHETIC_PT_BASELINE",{...b,exclusions:["/pt/admin"]}),/NOT_AUTHORIZED/);
});
test("Phase09 fingerprints bind specification scope and permit identity",()=>{
 const p=orchestrationFingerprint(build());
 for(const binding of [{...b,scopeId:"66666666-6666-4666-8666-666666666666"},
  {...b,specFingerprint:"c".repeat(64)},{...b,permitFingerprint:"d".repeat(64)}])
  assert.notEqual(orchestrationFingerprint(build(undefined,binding)),p);
});
test("Phase09 validates stage dependency identity and rejects duplicates",()=>{
 const plan=build();const bad=structuredClone(plan);
 bad.stages[1]!.dependencies=["finalization"];
 assert.throws(()=>validateOrchestrationPlan(bad),/INVALID_STAGE_DEPENDENCIES/);
 const duplicate=structuredClone(plan);duplicate.evaluations.push(duplicate.evaluations[0]!);
 assert.throws(()=>validateOrchestrationPlan(duplicate),/INVALID_PLANNED_EVALUATION/);
});
