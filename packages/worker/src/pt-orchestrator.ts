/** Phase09 bounded autonomous stage controller on the accepted private queue and Phase06 governor.
 * No external networking or new permit authority. */
import type {PoolClient} from "pg";
import {withWorkerTenant,uuid} from "../../database/src/index.js";
import {planFingerprint,evaluateRule,getRule} from "../../pt/src/detection.js";
import {type Evidence} from "../../pt/src/security-fixture.js";
import {type OrchestrationPlan,ORCHESTRATOR_ENGINE,buildOrchestrationPlan,
 orchestrationFingerprint,validateOrchestrationPlan} from "../../pt/src/orchestrator.js";
import {persistTerminalCoverage} from "../../pt/src/terminal-coverage.js";
import {persistOrchestrationTerminal} from "../../pt/src/orchestration-terminal.js";
import {governedPtDetectionInteraction,settlePtDetectionReservations,
 withGovernedPtDetectionPublication} from "./pt.js";

type StageRow={stage_id:string;stage_type:string;ordinal:number;status:string;
 planned:number;dependencies:string[];evaluation_keys:string[];claim_token:string|null};
type EvaluationRow={evaluation_key:string;state:"RESERVED"|"CONSUMED"|"UNCERTAIN";evidence:Evidence|null};
async function planAndStages(tenant:string,id:string):Promise<{plan:OrchestrationPlan;stages:StageRow[]}>{
 return withWorkerTenant(tenant,async tx=>{
  const p=await tx.query("SELECT o.plan,o.fingerprint,a.engine_version,j.permit_id,j.scope_id,j.target_id,s.specification_id,s.specification_version,s.spec_fingerprint,s.target_verification_version,s.target_scope_revision,s.fixture_id,s.operation_keys,s.exclusions,s.max_evaluations,s.rate_per_minute,s.max_concurrency,s.deadline_ms,r.token_hash,d.fixture_profile,d.rules,d.evaluations,d.plan_fingerprint FROM api_pt9_plans o JOIN api_assessments a ON a.id=o.assessment_id AND a.tenant_id=o.tenant_id JOIN api_pt_jobs j ON j.assessment_id=o.assessment_id JOIN api_pt_scopes s ON s.id=j.scope_id AND s.tenant_id=j.tenant_id JOIN api_pt_permits r ON r.id=j.permit_id JOIN api_pt_detection_plans d ON d.assessment_id=o.assessment_id WHERE o.assessment_id=$1",[id]);
  if(!p.rowCount||p.rows[0].engine_version!==ORCHESTRATOR_ENGINE)throw new Error("PT9_PLAN_OR_ENGINE_MISSING");
  const v=p.rows[0],plan=v.plan as OrchestrationPlan;
  validateOrchestrationPlan(plan);
  if(orchestrationFingerprint(plan)!==v.fingerprint)throw new Error("PT9_PLAN_FINGERPRINT_TAMPERED");
  const binding=plan.binding;
  if(binding.tenantId!==tenant||binding.targetId!==v.target_id||
   binding.scopeId!==v.scope_id||binding.permitId!==v.permit_id||
   binding.specificationId!==v.specification_id||binding.specificationVersion!==v.specification_version||
   binding.specFingerprint!==v.spec_fingerprint||binding.targetVerificationVersion!==v.target_verification_version||
   binding.targetScopeRevision!==v.target_scope_revision||binding.fixtureId!==v.fixture_id||
   binding.permitFingerprint!==v.token_hash||
   JSON.stringify([...binding.operationKeys].sort())!==JSON.stringify([...v.operation_keys].sort())||
   JSON.stringify([...binding.exclusions].sort())!==JSON.stringify([...v.exclusions].sort())||
   binding.maxEvaluations!==v.max_evaluations||binding.ratePerMinute!==v.rate_per_minute||
   binding.maxConcurrency!==v.max_concurrency||binding.deadlineMs!==v.deadline_ms)
   throw new Error("PT9_AUTHORITY_BINDING_MISMATCH");
  const ops=await tx.query("SELECT operation_key,method,path FROM api_inventory_operations WHERE specification_id=$1 AND method='GET'",[v.specification_id]);
  const reconstructed=buildOrchestrationPlan(plan.policyId,plan.profile,binding,ops.rows);
  if(orchestrationFingerprint(reconstructed)!==v.fingerprint)throw new Error("PT9_NONDETERMINISTIC_OR_STALE_PLAN");
  const detectionPlan={engineVersion:"pt-detection-v1",fixtureVersion:1,fixtureId:plan.fixtureId,
   profile:plan.profile,rules:plan.rules,evaluations:plan.evaluations,
   specFingerprint:binding.specFingerprint,scopeId:binding.scopeId};
  if(v.plan_fingerprint!==planFingerprint(detectionPlan)||v.fixture_profile!==plan.profile||
   JSON.stringify(v.rules)!==JSON.stringify(plan.rules)||JSON.stringify(v.evaluations)!==JSON.stringify(plan.evaluations))
   throw new Error("PT9_DETECTION_SUBPLAN_TAMPERED");
  const s=await tx.query("SELECT stage_id,stage_type,ordinal,status,planned,dependencies,evaluation_keys,claim_token FROM api_pt9_stages WHERE assessment_id=$1 ORDER BY ordinal",[id]);
  if(s.rowCount!==plan.stages.length)throw new Error("PT9_STAGE_COUNT_MISMATCH");
  const rows=s.rows as StageRow[];
  for(let i=0;i<rows.length;i++){
   const a=rows[i]!,b=plan.stages[i]!;
   if(a.stage_id!==b.id||a.stage_type!==b.type||a.ordinal!==i||a.planned!==b.budget||
    JSON.stringify(a.dependencies)!==JSON.stringify(b.dependencies)||
    JSON.stringify(a.evaluation_keys)!==JSON.stringify(b.evaluationKeys))
    throw new Error("PT9_STAGE_SNAPSHOT_TAMPERED");
  }
  return {plan,stages:rows};
 });
}
async function gated<T>(tenant:string,id:string,token:string,fn:(tx:PoolClient)=>Promise<T>):Promise<T>{
 const value=await withGovernedPtDetectionPublication(tenant,id,token,fn);
 if(value===null)throw new Error("PT9_GOVERNOR_OR_LEASE_DENIED");
 return value;
}
async function record(tx:PoolClient,tenant:string,id:string,stageId:string,code:string,details:unknown={}):Promise<void>{
 await tx.query("INSERT INTO api_pt9_decisions(id,tenant_id,assessment_id,stage_id,code,details) VALUES($1,$2,$3,$4,$5,$6::jsonb)",
  [uuid(),tenant,id,stageId,code,JSON.stringify(details)]);
}
/** Only the current fenced worker claim may resume a RUNNING stage. */
async function startStage(tenant:string,id:string,token:string,stageId:string):Promise<boolean>{
 return gated(tenant,id,token,async tx=>{
  const s=await tx.query("SELECT * FROM api_pt9_stages WHERE assessment_id=$1 AND stage_id=$2 FOR UPDATE",[id,stageId]);
  if(!s.rowCount)throw new Error("PT9_STAGE_NOT_FOUND");
  const row=s.rows[0] as StageRow;
  if(row.status==="COMPLETED")return false;
  if(!["PENDING","RUNNING"].includes(row.status))throw new Error("PT9_STAGE_TERMINAL");
  for(const dependency of row.dependencies){
   const d=await tx.query("SELECT status FROM api_pt9_stages WHERE assessment_id=$1 AND stage_id=$2",[id,dependency]);
   if(d.rows[0]?.status!=="COMPLETED")throw new Error("PT9_STAGE_DEPENDENCY_NOT_COMPLETED");
  }
  await tx.query("UPDATE api_pt9_stages SET status='RUNNING',claim_token=$3,started_at=COALESCE(started_at,now()) WHERE assessment_id=$1 AND stage_id=$2",
   [id,stageId,token]);
  await record(tx,tenant,id,stageId,row.status==="RUNNING"?"LEASED_RECOVERY":"STAGE_ADMITTED");
  return true;
 });
}
async function finishStage(tenant:string,id:string,token:string,plan:OrchestrationPlan,stageId:string):Promise<void>{
 await gated(tenant,id,token,async tx=>{
  const row=(await tx.query("SELECT status,claim_token FROM api_pt9_stages WHERE assessment_id=$1 AND stage_id=$2 FOR UPDATE",[id,stageId])).rows[0];
  if(row?.status!=="RUNNING"||row.claim_token!==token)throw new Error("PT9_STAGE_LEASE_MISMATCH");
  const stage=plan.stages.find(x=>x.id===stageId)!;
  const ledger=(await tx.query("SELECT evaluation_key,state,evidence FROM api_pt_detection_evaluations WHERE assessment_id=$1",[id])).rows as EvaluationRow[];
  const byKey=new Map(ledger.map(x=>[x.evaluation_key,x]));
  for(const evalKey of stage.evaluationKeys){
   const v=byKey.get(evalKey);
   if(v?.state!=="CONSUMED"||!v.evidence)throw new Error("PT9_STAGE_EVIDENCE_INCOMPLETE");
  }
  const results=[];
  for(const ruleId of stage.rules){
   const rule=getRule(ruleId);
   if(!rule)throw new Error("PT9_RULE_REVISION_UNAVAILABLE");
   const evidence=rule.cases.map(c=>byKey.get(rule.id+":"+c.caseId)?.evidence);
   if(evidence.some(x=>!x))throw new Error("PT9_RULE_EVIDENCE_INCOMPLETE");
   const evaluated=evaluateRule(rule,plan.profile,evidence as Evidence[]);
   if(!["PASS","OBSERVED"].includes(evaluated.status))throw new Error("PT9_RULE_EVIDENCE_INCONCLUSIVE");
   await tx.query("INSERT INTO api_pt_detection_results(id,tenant_id,assessment_id,rule_id,rule_revision,status,code,fingerprint,evidence) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb)",
    [uuid(),tenant,id,rule.id,rule.revision,evaluated.status,evaluated.code,evaluated.fingerprint,JSON.stringify(evaluated.evidence)]);
   results.push({ruleId:rule.id,status:evaluated.status,code:evaluated.code,fingerprint:evaluated.fingerprint});
  }
  const fingerprint=planFingerprint({plan:orchestrationFingerprint(plan),stageId,results,
   evaluations:stage.evaluationKeys.map(k=>({key:k,responseHash:byKey.get(k)!.evidence!.responseHash}))});
  await tx.query("UPDATE api_pt9_stages SET status='COMPLETED',finished_at=now(),evidence_fingerprint=$3,reason='EVIDENCE_RECONCILED' WHERE assessment_id=$1 AND stage_id=$2",
   [id,stageId,fingerprint]);
  await record(tx,tenant,id,stageId,"STAGE_EVIDENCE_COMPLETED",{fingerprint,results:results.length});
 });
}
async function publish(tenant:string,id:string,token:string,plan:OrchestrationPlan):Promise<void>{
 await gated(tenant,id,token,async tx=>{
  const stages=(await tx.query("SELECT stage_id,stage_type,ordinal,status,dependencies,evidence_fingerprint,started_at,finished_at,claim_token FROM api_pt9_stages WHERE assessment_id=$1 ORDER BY ordinal FOR UPDATE",[id])).rows;
  if(stages.length!==plan.stages.length||stages.slice(0,-1).some(x=>x.status!=="COMPLETED")||
   stages[stages.length-1]?.status!=="RUNNING"||stages[stages.length-1]?.claim_token!==token)
   throw new Error("PT9_FINAL_DEPENDENCIES_NOT_SATISFIED");
  const ledger=(await tx.query("SELECT evaluation_key,state,evidence FROM api_pt_detection_evaluations WHERE assessment_id=$1 ORDER BY evaluation_key",[id])).rows as EvaluationRow[];
  if(ledger.length!==plan.evaluations.length||ledger.some(e=>e.state!=="CONSUMED"||!e.evidence))
   throw new Error("PT9_FINAL_EVALUATION_INCOMPLETE");
  const result=(await tx.query("SELECT rule_id,rule_revision,status,code,fingerprint,evidence FROM api_pt_detection_results WHERE assessment_id=$1 ORDER BY rule_id",[id])).rows;
  if(result.length!==plan.rules.length||result.some(x=>!["PASS","OBSERVED"].includes(x.status)))
   throw new Error("PT9_FINAL_RULE_INCOMPLETE");
  const observations=result.filter(x=>x.status==="OBSERVED").map(x=>({
   ruleId:x.rule_id,revision:x.rule_revision,status:x.status,code:x.code,fingerprint:x.fingerprint,
   evidence:x.evidence,remediation:getRule(x.rule_id)?.remediation,impact:getRule(x.rule_id)?.impact,
   confidence:"HIGH",verifiedFixed:false}));
  const finishedFingerprint=planFingerprint({planFingerprint:orchestrationFingerprint(plan),
   stageId:"finalization",results:result.map(x=>({id:x.rule_id,fingerprint:x.fingerprint}))});
  await tx.query("UPDATE api_pt9_stages SET status='COMPLETED',finished_at=now(),evidence_fingerprint=$2,reason='IMMUTABLE_REPORT_PUBLISHED' WHERE assessment_id=$1 AND stage_id='finalization'",
   [id,finishedFingerprint]);
  const stageOutcomes=stages.map(({claim_token:_claimToken,...x},i)=>i===stages.length-1?
   {...x,status:"COMPLETED",evidence_fingerprint:finishedFingerprint}:x);
  const report={schemaVersion:"pt-orchestration-report-v1",orchestrationId:id,engineVersion:ORCHESTRATOR_ENGINE,
   policyId:plan.policyId,policyVersion:plan.policyVersion,planFingerprint:orchestrationFingerprint(plan),
   targetId:plan.binding.targetId,specificationId:plan.binding.specificationId,
   specFingerprint:plan.binding.specFingerprint,environment:"SYNTHETIC",scopeId:plan.binding.scopeId,
   permitFingerprint:plan.binding.permitFingerprint,fixtureId:plan.fixtureId,fixtureVersion:plan.fixtureVersion,
   profile:plan.profile,stages:stageOutcomes,ruleResults:result.map(x=>({ruleId:x.rule_id,status:x.status,code:x.code,fingerprint:x.fingerprint})),
   observations,coverage:{rulesPlanned:plan.rules.length,rulesExecuted:result.length,
    passed:result.length-observations.length,observed:observations.length,unknown:0},
   accounting:{planned:plan.evaluations.length,executed:ledger.length,uncertain:0,notRun:0},
   status:"COMPLETED",syntheticOnly:true,customerNetworkRequests:0,customerRuntimeVerified:false,
   verifiedFixed:false,confirmedCustomerVulnerabilities:[],
   limitations:["ISOLATED SYNTHETIC AUTONOMOUS API PT","NOT AUTHORIZED FOR LIVE CUSTOMER API TESTING",
    "REAL HOST AUTHORIZATION UNAVAILABLE","No evidence != safe","CI PASS != VERIFIED_FIXED"]};
  await tx.query("INSERT INTO api_pt9_reports(id,tenant_id,assessment_id,projection,fingerprint) VALUES($1,$2,$3,$4::jsonb,$5)",
   [uuid(),tenant,id,JSON.stringify(report),planFingerprint(report)]);
  await tx.query("UPDATE api_assessments SET status='COMPLETED',completed_at=now() WHERE id=$1 AND status='PROCESSING'",[id]);
  await record(tx,tenant,id,"finalization","ORCHESTRATION_COMPLETED",{observations:observations.length,planned:plan.evaluations.length});
  await tx.query("DELETE FROM api_queue.api_assessment_queue WHERE assessment_id=$1 AND claim_token=$2",[id,token]);
 });
}
async function fail(tenant:string,id:string,token:string,code:string):Promise<void>{
 if(!await settlePtDetectionReservations(tenant,id,token))return;
 await withWorkerTenant(tenant,async tx=>{
  const q=await tx.query("SELECT claim_token,locked_until FROM api_queue.api_assessment_queue WHERE assessment_id=$1 FOR UPDATE",[id]);
  if(q.rows[0]?.claim_token!==token||new Date(q.rows[0].locked_until).getTime()<=Date.now())return;
  const a=await tx.query("SELECT status FROM api_assessments WHERE id=$1 FOR UPDATE",[id]);
  if(a.rows[0]?.status!=="PROCESSING")return;
  await tx.query("UPDATE api_assessments SET status='FAILED',error_code=$2,completed_at=now() WHERE id=$1 AND status='PROCESSING'",[id,code]);
  await tx.query("UPDATE api_pt9_stages SET status=CASE WHEN status='RUNNING' THEN 'FAILED' ELSE 'BLOCKED' END,reason=$2,finished_at=now() WHERE assessment_id=$1 AND status IN('PENDING','RUNNING')",[id,code]);
  await persistTerminalCoverage(tx,tenant,id);
  await persistOrchestrationTerminal(tx,tenant,id,"FAILED",code);
  await tx.query("INSERT INTO api_pt_events(id,tenant_id,subject_id,action,details) VALUES($1,$2,$3,'PT9_ORCHESTRATION_FAILED',$4::jsonb)",
   [uuid(),tenant,id,JSON.stringify({code})]);
  await tx.query("DELETE FROM api_queue.api_assessment_queue WHERE assessment_id=$1 AND claim_token=$2",[id,token]);
 });
}
export type Pt9QualificationBarriers={afterEvaluation?:(completed:number)=>Promise<void>;
 afterCheckpoint?:(stageId:string)=>Promise<void>};
export async function processPtOrchestrationJob(tenant:string,id:string,token:string,
 barriers?:Pt9QualificationBarriers):Promise<void>{
 let count=0;
 try{
  const {plan}=await planAndStages(tenant,id);
  for(const stage of plan.stages){
   const started=await startStage(tenant,id,token,stage.id);
   if(!started)continue;
   if(stage.type==="FINALIZATION"){await publish(tenant,id,token,plan);return;}
   for(const item of plan.evaluations.filter(x=>stage.evaluationKeys.includes(x.evaluationKey))){
    const prior=await withWorkerTenant(tenant,async tx=>
     (await tx.query("SELECT state FROM api_pt_detection_evaluations WHERE assessment_id=$1 AND evaluation_key=$2",[id,item.evaluationKey])).rows[0]?.state as string|undefined);
    if(prior==="CONSUMED")continue;
    // A RESERVED or UNCERTAIN receipt is never replayed as an unapproved extra interaction.
    if(prior==="UNCERTAIN")throw new Error("PT9_UNCERTAIN_EVALUATION_NO_REPLAY");
    const result=await governedPtDetectionInteraction(tenant,id,token,{
     evaluationKey:item.evaluationKey,operationKey:item.operationKey,
     method:"GET",path:item.path,actor:item.actor,profile:plan.profile});
    if(result.status!=="CONSUMED")throw new Error("PT9_GOVERNED_EVALUATION_"+result.status+"_"+result.code);
    count++;
    if(barriers?.afterEvaluation)await barriers.afterEvaluation(count);
   }
   await finishStage(tenant,id,token,plan,stage.id);
   if(barriers?.afterCheckpoint)await barriers.afterCheckpoint(stage.id);
  }
  throw new Error("PT9_FINALIZATION_UNREACHABLE");
 }catch(e){
  // Only a deliberately injected isolated test-process death may leave checkpoints for takeover.
  // Production errors must always fail closed and settle conservatively.
  if(process.env.NODE_ENV==="test"&&barriers&&e instanceof Error&&e.message==="PT9_ISOLATED_PROCESS_EXIT")return;
  const code=e instanceof Error?e.message:"PT9_UNEXPECTED_ENGINE_FAILURE";
  await fail(tenant,id,token,code.slice(0,110).toUpperCase().replace(/[^A-Z0-9_]/g,"_"));
 }
}
