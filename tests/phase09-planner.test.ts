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


test("Phase09 scope revision and target identity changes affect signed canonical plan",()=>{
 const original=orchestrationFingerprint(build());
 for(const ctx of [
  {...b,targetScopeRevision:2},
  {...b,targetId:"77777777-7777-4777-8777-777777777777"},
  {...b,tenantId:"88888888-8888-4888-8888-888888888888"}
 ]){
  assert.notEqual(orchestrationFingerprint(build(undefined,ctx)),original);
 }
});
test("Phase09 unknown policy revision fails closed",()=>{
 const p=structuredClone(build());p.policyVersion="0.0.0";
 assert.throws(()=>validateOrchestrationPlan(p),/POLICY_REVISION_CHANGED/);
});
test("Phase09 unavailable fixture protocol revisions cannot be silently upgraded",()=>{
 const p=structuredClone(build());
 (p as unknown as {fixtureVersion:number}).fixtureVersion=2;
 assert.throws(()=>validateOrchestrationPlan(p),/ORCHESTRATION_PLAN_INVALID/);
});
test("Phase09 explicitly forbidden POST method cannot enter a stage plan",()=>{
 const altered=ops.map(x=>x.path==="/pt/admin"?{...x,method:"POST"}:x);
 assert.throws(()=>build(undefined,b,altered),/ORCHESTRATION_OPERATION_NOT_AUTHORIZED/);
});
test("Phase09 missing required trusted operation prevents admission",()=>{
 assert.throws(()=>build(undefined,b,ops.filter(x=>x.path!=="/pt/confidential")),/ORCHESTRATION_OPERATION_NOT_AUTHORIZED/);
});
test("Phase09 missing prerequisite stage identity is rejected",()=>{
 const p=structuredClone(build());p.stages[1]!.dependencies=["missing-stage"];
 assert.throws(()=>validateOrchestrationPlan(p),/INVALID_STAGE_DEPENDENCIES/);
});
test("Phase09 cycles and forward dependency edges cannot execute",()=>{
 const p=structuredClone(build());p.stages[1]!.dependencies=["finalization"];
 assert.throws(()=>validateOrchestrationPlan(p),/INVALID_STAGE_DEPENDENCIES/);
});
test("Phase09 unknown stage executor types fail closed",()=>{
 const p=structuredClone(build());
 (p.stages[1] as unknown as {type:string}).type="ARBITRARY_SCRIPT";
 assert.throws(()=>validateOrchestrationPlan(p),/INVALID_STAGE_DEPENDENCIES/);
});
test("Phase09 duplicate stage IDs and stage budget duplication are rejected",()=>{
 const p=structuredClone(build());p.stages[1]!.id="preflight";
 assert.throws(()=>validateOrchestrationPlan(p),/INVALID_STAGE_DEPENDENCIES/);
 const duplicate=structuredClone(build());duplicate.stages[2]!.evaluationKeys.push(duplicate.stages[1]!.evaluationKeys[0]!);
 assert.throws(()=>validateOrchestrationPlan(duplicate),/INVALID_STAGE_EVALUATION_OWNERSHIP/);
});
test("Phase09 excess planned evaluations fail before permit admission",()=>{
 assert.throws(()=>build(undefined,{...b,maxEvaluations:13}),/ORCHESTRATION_BUDGET_TOO_SMALL/);
 const plan=structuredClone(build());plan.maxEvaluations=plan.maxEvaluations+1;
 assert.throws(()=>validateOrchestrationPlan(plan),/INVALID_PLANNED_BUDGET/);
});
test("Phase09 rate and concurrency safety bounds cannot be increased",()=>{
 assert.throws(()=>build(undefined,{...b,ratePerMinute:13}),/ORCHESTRATION_BUDGET_TOO_SMALL/);
 assert.throws(()=>build(undefined,{...b,maxConcurrency:3}),/INVALID_AUTHORITY_BINDING/);
});
test("Phase09 duplicated or outdated canonical rule selection is rejected",()=>{
 const a=structuredClone(build());a.rules.push({...a.rules[0]!});
 assert.throws(()=>validateOrchestrationPlan(a),/RULE_REVISION_CHANGED/);
 const outdated=structuredClone(build());outdated.rules[0]!.revision="0.9.0";
 assert.throws(()=>validateOrchestrationPlan(outdated),/RULE_REVISION_CHANGED/);
});
test("Phase09 tampered trusted actor and evaluation cases cannot be substituted",()=>{
 const p=structuredClone(build());p.evaluations[0]!.actor="admin";
 assert.throws(()=>validateOrchestrationPlan(p),/INVALID_PLANNED_EVALUATION/);
 const altered=structuredClone(build());altered.evaluations[0]!.caseId="unapproved";
 assert.throws(()=>validateOrchestrationPlan(altered),/INVALID_PLANNED_EVALUATION/);
});
test("Phase09 unauthorized stage scope changes cannot acquire execution authority",()=>{
 const p=structuredClone(build());
 p.binding.operationKeys=["unauthorized-operation"];
 assert.throws(()=>validateOrchestrationPlan(p),/INVALID_PLANNED_EVALUATION/);
});
test("Phase09 plan deadline and excessive stages are bounded",()=>{
 assert.throws(()=>build(undefined,{...b,deadlineMs:60000}),/INVALID_AUTHORITY_BINDING/);
 const p=structuredClone(build());
 p.stages.push({...p.stages[5]!,id:"extra-stage"});
 assert.throws(()=>validateOrchestrationPlan(p),/ORCHESTRATION_PLAN_INVALID/);
});
