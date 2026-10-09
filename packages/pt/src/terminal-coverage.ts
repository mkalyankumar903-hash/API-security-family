/** Phase08: customer-readable terminal diagnostic, never a successful PT report.
 * All counts originate from immutable plans and the governed evaluation ledger. */
import type {PoolClient} from "pg";
import {createHash} from "node:crypto";
import {uuid} from "../../database/src/index.js";
import {evaluateRule,getRule,type RuleId} from "./detection.js";
import type {Evidence,Profile} from "./security-fixture.js";

type PlanRule={id:RuleId;revision:string};
type PlanEval={evaluationKey:string;ruleId:RuleId;caseId:string};
type Recorded={evaluation_key:string;state:"RESERVED"|"CONSUMED"|"UNCERTAIN";reason:string|null;evidence:Evidence|null};
export type TerminalRule={
 rule_id:string;rule_revision:string;status:"PASS"|"OBSERVED"|"INCONCLUSIVE"|"SKIPPED"|"BLOCKED"|"NOT_RUN";
 code:string;planned:number;executed:number;uncertain:number;notRun:number;
};
export type TerminalCoverage={
 schemaVersion:"pt-terminal-coverage-v1";assessmentId:string;status:"FAILED"|"CANCELLED";
 errorCode:string;fixtureProfile:string;rules:TerminalRule[];
 totals:{requestedRules:number;plannedEvaluations:number;executedEvaluations:number;uncertainEvaluations:number;notRunEvaluations:number};
 assessmentComplete:false;customerRuntimeVerified:false;verifiedFixed:false;syntheticOnly:true;customerNetworkRequests:0;
 notice:string;limitations:string[];
};
export function buildTerminalCoverage(id:string,status:"FAILED"|"CANCELLED",reason:string,profile:Profile,
 rules:PlanRule[],plan:PlanEval[],recorded:Recorded[]):TerminalCoverage{
 const lookup=new Map(recorded.map(x=>[x.evaluation_key,x]));
 const summaries:TerminalRule[]=rules.map(selected=>{
  const rule=getRule(selected.id);
  const cases=plan.filter(x=>x.ruleId===selected.id);
  const actual=cases.map(x=>lookup.get(x.evaluationKey));
  const executed=actual.filter(x=>x?.state==="CONSUMED"&&x.evidence!==null).length;
  const uncertain=actual.filter(x=>x?.state==="UNCERTAIN"||x?.state==="RESERVED"||
   (x?.state==="CONSUMED"&&!x.evidence)).length;
  const notRun=cases.length-executed-uncertain;
  const base={rule_id:selected.id,rule_revision:selected.revision,planned:cases.length,
   executed,uncertain,notRun};
  if(!rule||rule.revision!==selected.revision||cases.length!==rule.cases.length)
   return {...base,status:"INCONCLUSIVE" as const,code:"RULE_OR_PLAN_INCOMPATIBLE"};
  if(executed===cases.length&&notRun===0&&uncertain===0){
   const verdict=evaluateRule(rule,profile,actual.map(x=>x!.evidence!) as Evidence[]);
   return {...base,status:verdict.status,code:verdict.code};
  }
  if(uncertain>0||executed>0)return {...base,status:"INCONCLUSIVE" as const,code:"PARTIAL_OR_UNCERTAIN_EXECUTION"};
  if(reason.includes("REVOKED")||reason.includes("DENIED")||reason.includes("STOP")||reason.includes("BUDGET"))
   return {...base,status:"BLOCKED" as const,code:reason};
  return {...base,status:"NOT_RUN" as const,code:"ASSESSMENT_TERMINATED_BEFORE_RULE"};
 });
 const sum=(k:"planned"|"executed"|"uncertain"|"notRun")=>summaries.reduce((n,x)=>n+x[k],0);
 return {schemaVersion:"pt-terminal-coverage-v1",assessmentId:id,status,errorCode:reason,
  fixtureProfile:profile,rules:summaries,totals:{requestedRules:rules.length,plannedEvaluations:sum("planned"),
   executedEvaluations:sum("executed"),uncertainEvaluations:sum("uncertain"),notRunEvaluations:sum("notRun")},
  assessmentComplete:false,customerRuntimeVerified:false,verifiedFixed:false,syntheticOnly:true,customerNetworkRequests:0,
  notice:"Assessment incomplete — some security checks were not executed or lacked sufficient evidence.",
  limitations:["Failed or cancelled execution is not a successful PT report",
   "Missing evidence, blocked checks and unknown operations are not safe",
   "Synthetic fixture observations are not confirmed customer vulnerabilities",
   "No longer observed never establishes VERIFIED_FIXED"]};
}
/** Run inside the existing worker or cancellation transaction AFTER the terminal transition.
 * Append-only: never invent a diagnostic for a still-running job. */
export async function persistTerminalCoverage(tx:PoolClient,tenant:string,id:string):Promise<boolean>{
 const r=await tx.query(
  "SELECT a.status,a.error_code,p.rules,p.evaluations,p.fixture_profile FROM api_pt_detection_plans p JOIN api_assessments a ON a.id=p.assessment_id AND a.tenant_id=p.tenant_id WHERE p.assessment_id=$1",[id]);
 if(!r.rowCount||!["FAILED","CANCELLED"].includes(r.rows[0].status))return false;
 const x=r.rows[0] as {status:"FAILED"|"CANCELLED";error_code:string|null;rules:PlanRule[];evaluations:PlanEval[];fixture_profile:Profile};
 const evaluations=await tx.query(
  "SELECT evaluation_key,state,reason,evidence FROM api_pt_detection_evaluations WHERE assessment_id=$1 ORDER BY evaluation_key LIMIT 20",[id]);
 const summary=buildTerminalCoverage(id,x.status,x.error_code??(x.status==="CANCELLED"?"CANCELLED_BY_AUTHORITY":"UNKNOWN_FAILURE"),
  x.fixture_profile,x.rules,x.evaluations,evaluations.rows as Recorded[]);
 const snapshot=JSON.stringify(summary);
 const fingerprint=createHash("sha256").update(snapshot).digest("hex");
 const inserted=await tx.query(
  "INSERT INTO api_pt8_terminal_coverage(id,tenant_id,assessment_id,final_status,fingerprint,projection) VALUES($1,$2,$3,$4,$5,$6::jsonb) ON CONFLICT(tenant_id,assessment_id) DO NOTHING RETURNING id",
  [uuid(),tenant,id,x.status,fingerprint,snapshot]);
 return Boolean(inserted.rowCount);
}
