/** Phase 11 product contract: composes immutable offline and independently governed synthetic evidence.
 * No permit issuance, endpoint discovery, user-defined execution, or canonical Host finding promotion.
 */
import {planFingerprint,getRule} from "./detection.js";
import {orchestrationFingerprint,validateOrchestrationPlan,type OrchestrationPlan} from "./orchestrator.js";

export const AUTONOMOUS_VAPT_ENGINE="autonomous-api-vapt-v1" as const;
export const AUTONOMOUS_VAPT_SCHEMA="autonomous-api-vapt-plan-v1" as const;
export const AUTONOMOUS_VAPT_REPORT="autonomous-api-vapt-report-v1" as const;
export type VaptMode="OFFLINE_ONLY"|"GOVERNED_SYNTHETIC";
export type VaptOperation={key:string;method:string;path:string;authState:string};
export type VaptInput={
 tenantId:string;targetId:string;specificationId:string;specificationVersion:number;
 specFingerprint:string;inventoryFingerprint:string;targetVerificationVersion:number;
 targetScopeRevision:number;offlineEngine:"inventory-v1"|"inventory-v2";
 mode:VaptMode;operations:readonly VaptOperation[];ptPlan?:OrchestrationPlan|null;
};
export type VaptStage={id:"offline"|"governed-pt"|"correlation"|"report";engine:string;dependencies:string[];required:boolean};
export type VaptPlan={
 schemaVersion:typeof AUTONOMOUS_VAPT_SCHEMA;engineVersion:typeof AUTONOMOUS_VAPT_ENGINE;
 tenantId:string;targetId:string;specificationId:string;specificationVersion:number;
 specFingerprint:string;inventoryFingerprint:string;targetVerificationVersion:number;
 targetScopeRevision:number;mode:VaptMode;offlineEngine:"inventory-v1"|"inventory-v2";
 operations:VaptOperation[];ptPlanFingerprint:string|null;ptPolicyId:string|null;
 ptPolicyVersion:string|null;ptProfile:string|null;scopeId:string|null;permitId:string|null;
 permitFingerprint:string|null;fixtureId:string|null;fixtureVersion:number|null;
 rules:{id:string;revision:string}[];plannedEvaluations:number;stages:VaptStage[];
 syntheticOnly:true;customerNetworkRequests:0;realHostAuthorization:"UNAVAILABLE";
};
export class AutonomousVaptError extends Error {constructor(public code:string){super(code);}}
const deny=(code:string):never=>{throw new AutonomousVaptError(code);};
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HEX=/^[a-f0-9]{64}$/;
export function buildAutonomousVaptPlan(input:VaptInput):VaptPlan{
 if(!UUID.test(input.tenantId)||!UUID.test(input.targetId)||!UUID.test(input.specificationId)||
  !Number.isInteger(input.specificationVersion)||input.specificationVersion<1||
  !Number.isInteger(input.targetVerificationVersion)||input.targetVerificationVersion<1||
  !Number.isInteger(input.targetScopeRevision)||input.targetScopeRevision<0||
  !HEX.test(input.specFingerprint)||!HEX.test(input.inventoryFingerprint)||
  !["inventory-v1","inventory-v2"].includes(input.offlineEngine)||
  !["OFFLINE_ONLY","GOVERNED_SYNTHETIC"].includes(input.mode))
  deny("INVALID_AUTONOMOUS_VAPT_BINDING");
 const operations=[...input.operations].sort((a,b)=>a.key.localeCompare(b.key));
 if(operations.length>5000||new Set(operations.map(o=>o.key)).size!==operations.length||
  operations.some(o=>!o.key||o.key.length>500||!o.path.startsWith("/")||o.path.length>2000||
    !/^(GET|HEAD|OPTIONS|POST|PUT|PATCH|DELETE|TRACE)$/.test(o.method)||o.authState.length>64))
  deny("INVALID_VAPT_OPERATION_INVENTORY");
 const pt=input.ptPlan??null;
 if((input.mode==="GOVERNED_SYNTHETIC")!==Boolean(pt))
  deny("SYNTHETIC_PLAN_REQUIRED_OR_FORBIDDEN");
 if(pt){
  validateOrchestrationPlan(pt);
  const binding=pt.binding;
  if(binding.tenantId!==input.tenantId||binding.targetId!==input.targetId||
   binding.specificationId!==input.specificationId||
   binding.specificationVersion!==input.specificationVersion||
   binding.specFingerprint!==input.specFingerprint||
   binding.targetVerificationVersion!==input.targetVerificationVersion||
   binding.targetScopeRevision!==input.targetScopeRevision||
   pt.evaluations.length>20||
   pt.evaluations.some(e=>!operations.some(o=>o.key===e.operationKey&&o.method==="GET")))
   deny("PT_PLAN_CONTEXT_MISMATCH");
 }
 const stages:VaptStage[]=[
  {id:"offline",engine:input.offlineEngine,dependencies:[],required:true},
  ...(pt?[{id:"governed-pt" as const,engine:"pt-orchestrator-v1",dependencies:["offline"],required:true}]:[]),
  {id:"correlation",engine:"autonomous-api-vapt-v1",dependencies:pt?["offline","governed-pt"]:["offline"],required:true},
  {id:"report",engine:"autonomous-api-vapt-v1",dependencies:["correlation"],required:true}
 ];
 return {schemaVersion:AUTONOMOUS_VAPT_SCHEMA,engineVersion:AUTONOMOUS_VAPT_ENGINE,
  tenantId:input.tenantId,targetId:input.targetId,specificationId:input.specificationId,
  specificationVersion:input.specificationVersion,specFingerprint:input.specFingerprint,
  inventoryFingerprint:input.inventoryFingerprint,targetVerificationVersion:input.targetVerificationVersion,
  targetScopeRevision:input.targetScopeRevision,mode:input.mode,offlineEngine:input.offlineEngine,
  operations,ptPlanFingerprint:pt?orchestrationFingerprint(pt):null,
  ptPolicyId:pt?.policyId??null,ptPolicyVersion:pt?.policyVersion??null,ptProfile:pt?.profile??null,
  scopeId:pt?.binding.scopeId??null,permitId:pt?.binding.permitId??null,
  permitFingerprint:pt?.binding.permitFingerprint??null,fixtureId:pt?.fixtureId??null,
  fixtureVersion:pt?.fixtureVersion??null,rules:pt?.rules??[],
  plannedEvaluations:pt?.evaluations.length??0,stages,syntheticOnly:true,
  customerNetworkRequests:0,realHostAuthorization:"UNAVAILABLE"};
}
export const autonomousVaptFingerprint=(plan:VaptPlan):string=>planFingerprint(plan);
export function validateAutonomousVaptPlan(input:VaptInput,stored:VaptPlan):void{
 const rebuilt=buildAutonomousVaptPlan(input);
 if(autonomousVaptFingerprint(rebuilt)!==autonomousVaptFingerprint(stored)||
  stored.schemaVersion!==AUTONOMOUS_VAPT_SCHEMA||stored.engineVersion!==AUTONOMOUS_VAPT_ENGINE||
  stored.syntheticOnly!==true||stored.customerNetworkRequests!==0)
  deny("AUTONOMOUS_VAPT_PLAN_TAMPERED");
}

export type OfflineObservation={
 ruleId:string;ruleRevision:string;operationKey:string|null;fingerprint:string;
 category:string;impact:string;confidence:string;explanation:string;remediation:string;
};
export type SyntheticObservation={
 ruleId:string;revision:string;fingerprint:string;code:string;
 remediation:string;impact:string;confidence:string;
};
export type UnifiedObservation={
 key:string;source:"SPEC_ONLY"|"SYNTHETIC_PT";ruleId:string;revision:string;
 operationKey:string|null;evidenceFingerprint:string;category:string;
 impact:string;confidence:string;explanation:string;remediation:string;
 priority:{policy:"autonomous-api-vapt-triage-v1";rank:number;reason:string};
 correlation:"SPEC_ONLY_UNVERIFIED_RUNTIME"|"SYNTHETIC_ONLY_OBSERVATION";
 syntheticOnly:true;customerVulnerabilityConfirmed:false;verifiedFixed:false;
};
export type Correlation={key:string;type:"SPEC_AND_SYNTHETIC_CORRELATED";
 relationship:"RELATED_NOT_EQUIVALENT";operationKey:string;specKeys:string[];ptKeys:string[];
 limitation:string};
const RELATED:Readonly<Record<string,readonly string[]>>={
 "API03_AUTH_UNDECLARED":["PT-AUTH-ANONYMOUS"],
 "API03_AUTH_EXPLICIT_NONE":["PT-AUTH-ANONYMOUS"],
 "API03_AUTH_SENSITIVE_ROUTE":["PT-AUTH-ANONYMOUS","PT-BOLA-CROSS-USER","PT-FUNCTION-ROLE"],
 "API03_RESPONSE_SENSITIVE_FIELD":["PT-SENSITIVE-FIELD"]
};
const impactLevel:Record<string,number>={INFORMATIONAL:0,LOW:1,MEDIUM:2,HIGH:3};
function priority(impact:string,source:"SPEC_ONLY"|"SYNTHETIC_PT",confidence:string){
 const level=impactLevel[impact]??0;
 const rank=level*10+(source==="SYNTHETIC_PT"?5:0)+(confidence==="HIGH"?1:0);
 return {policy:"autonomous-api-vapt-triage-v1" as const,rank,
  reason:source==="SPEC_ONLY"?"Specification declaration only; runtime security unverified":
   "Evidence from governed synthetic fixture only; customer runtime security unverified"};
}
export function correlateAutonomousVaptEvidence(context:{
 tenantId:string;targetId:string;specFingerprint:string;fixtureId:string|null;
 fixtureVersion:number|null;profile:string|null;ptRuleOperations:Record<string,string>;
},offline:readonly OfflineObservation[],synthetic:readonly SyntheticObservation[]):{
 observations:UnifiedObservation[];relationships:Correlation[];
}{
 const {tenantId,targetId,specFingerprint,fixtureId,fixtureVersion,profile,ptRuleOperations}=context;
 if(!UUID.test(tenantId)||!UUID.test(targetId)||!HEX.test(specFingerprint))
  deny("INVALID_CORRELATION_CONTEXT");
 const observations:UnifiedObservation[]=[];
 for(const f of offline){
  if(!f.ruleId.startsWith("API03_")||!HEX.test(f.fingerprint))
   deny("INVALID_OFFLINE_PROVENANCE");
  const key=planFingerprint({tenantId,targetId,specFingerprint,engine:"inventory-v1",
   rule:f.ruleId,revision:f.ruleRevision,operationKey:f.operationKey??null,evidence:f.fingerprint});
  observations.push({key,source:"SPEC_ONLY",ruleId:f.ruleId,revision:f.ruleRevision,
   operationKey:f.operationKey,evidenceFingerprint:f.fingerprint,category:f.category,
   impact:f.impact,confidence:f.confidence,explanation:f.explanation,remediation:f.remediation,
   priority:priority(f.impact,"SPEC_ONLY",f.confidence),correlation:"SPEC_ONLY_UNVERIFIED_RUNTIME",
   syntheticOnly:true,customerVulnerabilityConfirmed:false,verifiedFixed:false});
 }
 for(const f of synthetic){
  const rule=getRule(f.ruleId);
  const operationKey=ptRuleOperations[f.ruleId];
  if(!fixtureId||fixtureVersion===null||!profile||!rule||
   rule.revision!==f.revision||!HEX.test(f.fingerprint)||!operationKey)
   throw new AutonomousVaptError("INVALID_SYNTHETIC_PROVENANCE");
  const key=planFingerprint({tenantId,targetId,specFingerprint,fixtureId,fixtureVersion,
   profile,engine:"pt-detection-v1",rule:f.ruleId,revision:f.revision,operationKey});
  observations.push({key,source:"SYNTHETIC_PT",ruleId:f.ruleId,revision:f.revision,
   operationKey,evidenceFingerprint:f.fingerprint,category:rule.category,
   impact:f.impact,confidence:f.confidence,explanation:f.code,remediation:f.remediation,
   priority:priority(f.impact,"SYNTHETIC_PT",f.confidence),correlation:"SYNTHETIC_ONLY_OBSERVATION",
   syntheticOnly:true,customerVulnerabilityConfirmed:false,verifiedFixed:false});
 }
 const dedup=new Map<string,UnifiedObservation>();
 for(const x of observations){
  const prior=dedup.get(x.key);
  if(prior&&prior.evidenceFingerprint!==x.evidenceFingerprint)
   deny("DUPLICATE_FINDING_PROVENANCE_CONFLICT");
  dedup.set(x.key,x);
 }
 const unified=[...dedup.values()].sort((a,b)=>b.priority.rank-a.priority.rank||a.key.localeCompare(b.key));
 const relations:Correlation[]=[];
 const offlineRows=unified.filter(x=>x.source==="SPEC_ONLY");
 const ptRows=unified.filter(x=>x.source==="SYNTHETIC_PT");
 for(const x of offlineRows){
  const related=ptRows.filter(p=>p.operationKey&&x.operationKey===p.operationKey&&
   (RELATED[x.ruleId]??[]).includes(p.ruleId));
  if(!related.length)continue;
  const ptKeys=related.map(p=>p.key).sort();
  const key=planFingerprint({tenantId,targetId,specFingerprint,offlineKey:x.key,ptKeys,
   fixtureId,fixtureVersion,profile,relationship:"RELATED_NOT_EQUIVALENT"});
  relations.push({key,type:"SPEC_AND_SYNTHETIC_CORRELATED",
   relationship:"RELATED_NOT_EQUIVALENT",operationKey:x.operationKey!,specKeys:[x.key],
   ptKeys,limitation:"Related specification and synthetic fixture observations do not confirm a customer vulnerability"});
 }
 relations.sort((a,b)=>a.key.localeCompare(b.key));
 return {observations:unified,relationships:relations};
}
