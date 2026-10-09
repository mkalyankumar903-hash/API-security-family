/** Deterministic and strictly synthetic Phase09 planner. Never an authorization issuer. */
import {RULES,planFingerprint,type RuleId} from "./detection.js";
import {DETECTION_FIXTURE,isProfile,type Profile} from "./security-fixture.js";

export const ORCHESTRATOR_ENGINE="pt-orchestrator-v1" as const;
export const ORCHESTRATOR_SCHEMA="pt-orchestrator-plan-v1" as const;
export const POLICIES={
 SYNTHETIC_PT_BASELINE:{version:"1.0.0",ids:RULES.map(x=>x.id)},
 SYNTHETIC_PT_AUTHORIZATION_FOCUSED:{version:"1.0.0",ids:["PT-BOLA-CROSS-USER","PT-FUNCTION-ROLE"]},
 SYNTHETIC_PT_DATA_EXPOSURE_FOCUSED:{version:"1.0.0",ids:["PT-SENSITIVE-FIELD","PT-CONFIDENTIAL-CACHE"]},
 SYNTHETIC_PT_COMPLETE_SUPPORTED:{version:"1.0.0",ids:RULES.map(x=>x.id)}
} as const;
export type PolicyId=keyof typeof POLICIES;
export type Operation={operation_key:string;method:string;path:string};
export type Binding={
 tenantId:string;targetId:string;environment:"SYNTHETIC";specificationId:string;
 specificationVersion:number;specFingerprint:string;targetVerificationVersion:number;
 targetScopeRevision:number;scopeId:string;fixtureId:string;permitId:string;
 permitFingerprint:string;operationKeys:string[];exclusions:string[];
 maxEvaluations:number;ratePerMinute:number;maxConcurrency:number;deadlineMs:number;
};
export type Evaluation={evaluationKey:string;ruleId:RuleId;caseId:string;operationKey:string;
 method:"GET";path:string;actor:string};
export type Stage={id:string;type:"PREFLIGHT"|"AUTHENTICATION"|"AUTHORIZATION"|"RESPONSE"|"RECONCILIATION"|"FINALIZATION";
 dependencies:string[];rules:RuleId[];evaluationKeys:string[];budget:number};
export type OrchestrationPlan={
 schemaVersion:typeof ORCHESTRATOR_SCHEMA;engineVersion:typeof ORCHESTRATOR_ENGINE;
 policyId:PolicyId;policyVersion:string;fixtureId:typeof DETECTION_FIXTURE;fixtureVersion:1;profile:Profile;
 binding:Binding;rules:{id:RuleId;revision:string}[];evaluations:Evaluation[];
 stages:Stage[];maxEvaluations:number;syntheticOnly:true;customerNetworkRequests:0;
};
export class OrchestratorPlanError extends Error {constructor(public code:string){super(code);}}
const deny=(code:string):never=>{throw new OrchestratorPlanError(code);};
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
function assertBinding(b:Binding):void{
 if(!UUID.test(b.tenantId)||!UUID.test(b.targetId)||!UUID.test(b.scopeId)||
  !UUID.test(b.specificationId)||!UUID.test(b.permitId)||b.environment!=="SYNTHETIC"||
  b.fixtureId!==DETECTION_FIXTURE||!/^[a-f0-9]{64}$/.test(b.specFingerprint)||
  !/^[a-f0-9]{64}$/.test(b.permitFingerprint)||!Number.isInteger(b.specificationVersion)||
  b.specificationVersion<1||!Number.isInteger(b.targetScopeRevision)||
  !Number.isInteger(b.targetVerificationVersion)||
  !Number.isInteger(b.maxEvaluations)||b.maxEvaluations<1||b.maxEvaluations>30||
  !Number.isInteger(b.ratePerMinute)||b.ratePerMinute<1||b.ratePerMinute>20||
  !Number.isInteger(b.maxConcurrency)||b.maxConcurrency<1||b.maxConcurrency>2||
  !Number.isInteger(b.deadlineMs)||b.deadlineMs<1000||b.deadlineMs>30000||
  !Array.isArray(b.operationKeys)||b.operationKeys.length<1||b.operationKeys.length>20||
  !Array.isArray(b.exclusions)||b.exclusions.length>20||
  new Set(b.operationKeys).size!==b.operationKeys.length)deny("INVALID_AUTHORITY_BINDING");
}
export function buildOrchestrationPlan(policyId:string,profile:unknown,binding:Binding,operations:readonly Operation[]):OrchestrationPlan{
 if(!Object.prototype.hasOwnProperty.call(POLICIES,policyId))return deny("UNKNOWN_ORCHESTRATION_POLICY");
 if(!isProfile(profile))return deny("UNKNOWN_TRUSTED_FIXTURE_PROFILE");
 assertBinding(binding);
 const policy=POLICIES[policyId as PolicyId];
 const rules=RULES.filter(r=>(policy.ids as readonly string[]).includes(r.id))
  .map(r=>({id:r.id,revision:r.revision}));
 if(!rules.length||rules.length>8)return deny("INVALID_POLICY_RULE_SELECTION");
 const evals:Evaluation[]=[];
 for(const selected of rules){
  const rule=RULES.find(r=>r.id===selected.id)!;
  const candidates=operations.filter(op=>op.path===rule.path&&op.method==="GET"&&binding.operationKeys.includes(op.operation_key));
  if(candidates.length!==1||binding.exclusions.includes(rule.path))
   return deny("ORCHESTRATION_OPERATION_NOT_AUTHORIZED");
  const op=candidates[0]!;
  for(const c of rule.cases){
   evals.push({evaluationKey:rule.id+":"+c.caseId,ruleId:rule.id,caseId:c.caseId,
    operationKey:op.operation_key,method:"GET",path:c.path,actor:c.actor});
  }
 }
 if(new Set(evals.map(x=>x.evaluationKey)).size!==evals.length)
  return deny("DUPLICATE_EVALUATION_IDENTITY");
 if(evals.length>20||evals.length>binding.maxEvaluations||evals.length>binding.ratePerMinute)
  return deny("ORCHESTRATION_BUDGET_TOO_SMALL");
 const stages:Stage[]=[];
 function add(id:string,type:Stage["type"],selected:RuleId[]):void{
  const evaluationKeys=evals.filter(x=>selected.includes(x.ruleId)).map(x=>x.evaluationKey);
  stages.push({id,type,dependencies:stages.length?[stages[stages.length-1]!.id]:[],
   rules:selected,evaluationKeys,budget:evaluationKeys.length});
 }
 add("preflight","PREFLIGHT",[]);
 for(const [id,type,categories] of [
  ["authentication","AUTHENTICATION",["AUTHENTICATION"]],
  ["authorization","AUTHORIZATION",["OBJECT_AUTHORIZATION","FUNCTION_AUTHORIZATION"]],
  ["response","RESPONSE",["SENSITIVE_RESPONSE","RESPONSE_CONTROL"]]
 ] as const){
  const selected=rules.filter(x=>categories.some(cat=>RULES.find(r=>r.id===x.id)!.category===cat)).map(x=>x.id);
  if(selected.length)add(id,type,selected);
 }
 add("reconciliation","RECONCILIATION",[]);
 add("finalization","FINALIZATION",[]);
 if(stages.length>6||stages.some(x=>x.dependencies.length>1)||stages.reduce((n,x)=>n+x.budget,0)!==evals.length)
  return deny("INVALID_STAGE_GRAPH");
 const plan:OrchestrationPlan={schemaVersion:ORCHESTRATOR_SCHEMA,engineVersion:ORCHESTRATOR_ENGINE,
  policyId:policyId as PolicyId,policyVersion:policy.version,fixtureId:DETECTION_FIXTURE,fixtureVersion:1,
  profile,binding:{...binding,operationKeys:[...binding.operationKeys].sort(),exclusions:[...binding.exclusions].sort()},
  rules,evaluations:evals,stages,maxEvaluations:evals.length,syntheticOnly:true,customerNetworkRequests:0};
 validateOrchestrationPlan(plan);
 return plan;
}
export function validateOrchestrationPlan(plan:OrchestrationPlan):void{
 if(plan.schemaVersion!==ORCHESTRATOR_SCHEMA||plan.engineVersion!==ORCHESTRATOR_ENGINE||
  plan.fixtureId!==DETECTION_FIXTURE||plan.fixtureVersion!==1||!isProfile(plan.profile)||
  plan.syntheticOnly!==true||plan.customerNetworkRequests!==0||
  plan.stages.length<3||plan.stages.length>6)return deny("ORCHESTRATION_PLAN_INVALID");
 assertBinding(plan.binding);
 if(!Object.prototype.hasOwnProperty.call(POLICIES,plan.policyId)||
  plan.policyVersion!==POLICIES[plan.policyId].version)return deny("POLICY_REVISION_CHANGED");
 const ids=new Set<string>(),keys=new Set<string>();
 for(const stage of plan.stages){
  if(ids.has(stage.id)||stage.dependencies.some(d=>d===stage.id||!ids.has(d))||
   !["PREFLIGHT","AUTHENTICATION","AUTHORIZATION","RESPONSE","RECONCILIATION","FINALIZATION"].includes(stage.type))
   return deny("INVALID_STAGE_DEPENDENCIES");
  ids.add(stage.id);
 }
 for(const e of plan.evaluations){
  if(keys.has(e.evaluationKey)||e.method!=="GET"||!plan.binding.operationKeys.includes(e.operationKey)||
   plan.binding.exclusions.includes(e.path))return deny("INVALID_PLANNED_EVALUATION");
  keys.add(e.evaluationKey);
 }
 if(plan.maxEvaluations!==plan.evaluations.length||
  plan.stages.reduce((n,s)=>n+s.budget,0)!==plan.maxEvaluations||
  plan.maxEvaluations>plan.binding.maxEvaluations||plan.maxEvaluations>plan.binding.ratePerMinute)
  return deny("INVALID_PLANNED_BUDGET");
 for(const rule of plan.rules){
  if(!RULES.some(r=>r.id===rule.id&&r.revision===rule.revision))return deny("RULE_REVISION_CHANGED");
 }
}
export const orchestrationFingerprint=(plan:OrchestrationPlan)=>planFingerprint(plan);
