/** Phase 11 parent publication over completed existing child authorities.
 * No synthetic interaction, permit issue, network operation or queue override occurs here.
 */
import {withWorkerTenant,uuid} from "../../database/src/index.js";
import {planFingerprint,getRule} from "../../pt/src/detection.js";
import {buildAutonomousVaptPlan,autonomousVaptFingerprint,correlateAutonomousVaptEvidence,
 AUTONOMOUS_VAPT_REPORT,type VaptPlan,type VaptInput,
 type OfflineObservation,type SyntheticObservation} from "../../pt/src/autonomous-vapt.js";
import {orchestrationFingerprint,type OrchestrationPlan} from "../../pt/src/orchestrator.js";

const VALID_HEX=/^[0-9a-f]{64}$/;
type Child={id:string;status:string;engine_version:string;error_code:string|null};
export async function processAutonomousVaptJob(tenant:string,id:string,token:string):Promise<void>{
 await withWorkerTenant(tenant,async tx=>{
  // Canonical lock order matches Phase06: stop, target/permit, private queue,
  // assessment. The parent is an aggregation job, never a runtime permit.
  const v=(await tx.query("SELECT v.*,a.status AS parent_status FROM api_vapt11_assessments v JOIN api_assessments a ON a.id=v.parent_assessment_id AND a.tenant_id=v.tenant_id WHERE v.parent_assessment_id=$1",[id])).rows[0];
  if(!v)throw new Error("VAPT11_PARENT_NOT_FOUND");
  const plan=v.plan as VaptPlan;
  if(plan.engineVersion!=="autonomous-api-vapt-v1"||
   plan.schemaVersion!=="autonomous-api-vapt-plan-v1"||
   autonomousVaptFingerprint(plan)!==v.fingerprint||plan.tenantId!==tenant||
   plan.targetId!==v.target_id||plan.specificationId!==v.specification_id)
   throw new Error("VAPT11_IMMUTABLE_PLAN_INVALID");
  const stop=await tx.query("SELECT enabled FROM api_pt_stop WHERE tenant_id=$1 FOR UPDATE",[tenant]);
  const target=await tx.query("SELECT lifecycle,environment,verification_version,scope_revision FROM api_targets WHERE id=$1 FOR UPDATE",[v.target_id]);
  let permit:{id:string;revoked_at:string|null;expires_at:string}|null=null;
  if(v.pt_assessment_id){
   permit=(await tx.query("SELECT p.id,p.revoked_at,p.expires_at FROM api_pt_jobs j JOIN api_pt_permits p ON p.id=j.permit_id AND p.tenant_id=j.tenant_id WHERE j.assessment_id=$1 FOR UPDATE OF p",[v.pt_assessment_id])).rows[0]??null;
  }
  const q=await tx.query("SELECT claim_token,locked_until>clock_timestamp() AS lease_valid FROM api_queue.api_assessment_queue WHERE assessment_id=$1 FOR UPDATE",[id]);
  if(q.rows[0]?.claim_token!==token||q.rows[0]?.lease_valid!==true)
   throw new Error("VAPT11_PARENT_LEASE_LOST");
  const p=await tx.query("SELECT status FROM api_assessments WHERE id=$1 FOR UPDATE",[id]);
  if(p.rows[0]?.status!=="PROCESSING")throw new Error("VAPT11_PARENT_NOT_PROCESSING");
  const children=await tx.query("SELECT id,status,engine_version,error_code FROM api_assessments WHERE id=ANY($1::uuid[]) FOR UPDATE",
   [[v.offline_assessment_id,...(v.pt_assessment_id?[v.pt_assessment_id]:[])]]);
  const offline=children.rows.find(x=>x.id===v.offline_assessment_id) as Child|undefined;
  const pt=children.rows.find(x=>x.id===v.pt_assessment_id) as Child|undefined;
  const failure=offline?.status!=="COMPLETED"?"OFFLINE_COMPONENT_"+(offline?.status??"MISSING"):
   v.pt_assessment_id&&pt?.status!=="COMPLETED"?"PT_COMPONENT_"+(pt?.status??"MISSING"):
   !target.rowCount?"TARGET_MISSING":
   target.rows[0].lifecycle!=="ACTIVE"?"TARGET_NOT_ACTIVE":
   target.rows[0].verification_version!==plan.targetVerificationVersion||
    target.rows[0].scope_revision!==plan.targetScopeRevision?"TARGET_AUTHORITY_CHANGED":
   v.pt_assessment_id&&(
    target.rows[0].environment!=="SYNTHETIC"||stop.rows[0]?.enabled===true||
    !permit||permit.id!==plan.permitId||permit.revoked_at||
    new Date(permit.expires_at).getTime()<=Date.now()
   )?"GOVERNED_PT_AUTHORITY_NO_LONGER_CURRENT":null;
  if(failure){
   const terminal={schemaVersion:"autonomous-api-vapt-terminal-v1",assessmentId:id,
    status:"FAILED",code:failure,mode:plan.mode,
    components:children.rows.map(x=>({id:x.id,engine:x.engine_version,status:x.status,errorCode:x.error_code})),
    offlineEvidencePreserved:offline?.status==="COMPLETED",
    fullAuthorizedVaptCompleted:false,verifiedFixed:false,customerRuntimeVerified:false,
    customerNetworkRequests:0,
    limitations:["INCOMPLETE ASSESSMENT","NO EVIDENCE != SAFE","No synthetic fixture confirms a real customer vulnerability"]};
   await tx.query("INSERT INTO api_vapt11_terminal(id,tenant_id,parent_assessment_id,status,code,projection,fingerprint) VALUES($1,$2,$3,'FAILED',$4,$5::jsonb,$6)",
    [uuid(),tenant,id,failure,JSON.stringify(terminal),planFingerprint(terminal)]);
   await tx.query("UPDATE api_assessments SET status='FAILED',error_code=$2,completed_at=now() WHERE id=$1 AND status='PROCESSING'",[id,failure]);
   await tx.query("INSERT INTO api_vapt11_events(id,tenant_id,parent_assessment_id,code,details) VALUES($1,$2,$3,'PARENT_FAILED',$4::jsonb)",
    [uuid(),tenant,id,JSON.stringify({code:failure})]);
   await tx.query("DELETE FROM api_queue.api_assessment_queue WHERE assessment_id=$1 AND claim_token=$2",[id,token]);
   return;
  }
  // Recompute the admitted logical plan from immutable inventory and the
  // accepted Phase09 PT plan. Never use client-supplied child success claims.
  const inv=(await tx.query("SELECT version_number,raw_fingerprint,normalized_fingerprint FROM api_spec_inventories WHERE specification_id=$1",[v.specification_id])).rows[0];
  if(!inv||plan.specificationVersion!==inv.version_number||
   plan.specFingerprint!==inv.raw_fingerprint||plan.inventoryFingerprint!==inv.normalized_fingerprint)
   throw new Error("VAPT11_INVENTORY_CHANGED");
  const ops=(await tx.query("SELECT operation_key AS key,method,path,auth_state AS \"authState\" FROM api_inventory_operations WHERE specification_id=$1 ORDER BY operation_key",[v.specification_id])).rows;
  const phase9=v.pt_assessment_id?(await tx.query(
   "SELECT plan,fingerprint FROM api_pt9_plans WHERE assessment_id=$1",[v.pt_assessment_id])).rows[0]:null;
  if(v.pt_assessment_id&&(!phase9||orchestrationFingerprint(phase9.plan as OrchestrationPlan)!==phase9.fingerprint||
   plan.ptPlanFingerprint!==phase9.fingerprint))
   throw new Error("VAPT11_PT_PLAN_TAMPERED");
  const reconstructed=buildAutonomousVaptPlan({tenantId:tenant,targetId:v.target_id,
   specificationId:v.specification_id,specificationVersion:inv.version_number,
   specFingerprint:inv.raw_fingerprint,inventoryFingerprint:inv.normalized_fingerprint,
   targetVerificationVersion:plan.targetVerificationVersion,targetScopeRevision:plan.targetScopeRevision,
   offlineEngine:plan.offlineEngine,mode:plan.mode,operations:ops,
   ptPlan:phase9?.plan as OrchestrationPlan|undefined} satisfies VaptInput);
  if(autonomousVaptFingerprint(reconstructed)!==v.fingerprint)
   throw new Error("VAPT11_NONDETERMINISTIC_OR_TAMPERED_PLAN");
  const offlineReport=(await tx.query(
   "SELECT projection FROM api_reports WHERE assessment_id=$1",[v.offline_assessment_id])).rows[0]?.projection;
  if(!offlineReport||offlineReport.mode!=="SPEC_ONLY"||
   offlineReport.assessmentId!==v.offline_assessment_id||
   offlineReport.rawFingerprint!==plan.specFingerprint||
   offlineReport.normalizedFingerprint!==plan.inventoryFingerprint)
   throw new Error("VAPT11_OFFLINE_REPORT_INTEGRITY_INVALID");
  let ptReport: {status:string;syntheticOnly:boolean;customerRuntimeVerified:boolean;verifiedFixed:boolean;
  planFingerprint:string;accounting:{executed:number};coverage:{passed:number;rulesExecuted:number};
  observations:{ruleId:string;revision:string;fingerprint:string;code:string;impact:string;
    confidence:string;remediation:string}[]}|null=null;
  if(v.pt_assessment_id){
   ptReport=(await tx.query("SELECT projection FROM api_pt9_reports WHERE assessment_id=$1",[v.pt_assessment_id])).rows[0]?.projection;
   const stageStates=(await tx.query("SELECT stage_id,status FROM api_pt9_stages WHERE assessment_id=$1",[v.pt_assessment_id])).rows;
   const evals=(await tx.query("SELECT state FROM api_pt_detection_evaluations WHERE assessment_id=$1",[v.pt_assessment_id])).rows;
   if(!ptReport||ptReport.status!=="COMPLETED"||ptReport.syntheticOnly!==true||
    ptReport.customerRuntimeVerified!==false||ptReport.verifiedFixed!==false||
    ptReport.planFingerprint!==plan.ptPlanFingerprint||
    stageStates.length!==phase9.plan.stages.length||stageStates.some(x=>x.status!=="COMPLETED")||
    evals.length!==plan.plannedEvaluations||evals.some(x=>x.state!=="CONSUMED")||
    ptReport.accounting?.executed!==evals.length)
    throw new Error("VAPT11_PT_REPORT_INTEGRITY_INVALID");
  }
  const raw=(await tx.query("SELECT rule_id,rule_version,operation_key,stable_fingerprint,category,severity,evidence_confidence,explanation,remediation FROM api_findings WHERE assessment_id=$1 ORDER BY rule_id,stable_fingerprint",[v.offline_assessment_id])).rows;
  const offlineFindings:OfflineObservation[]=raw.map(x=>({
   ruleId:x.rule_id,ruleRevision:x.rule_version,operationKey:x.operation_key,
   fingerprint:x.stable_fingerprint,category:x.category,impact:x.severity??"LOW",
   confidence:x.evidence_confidence??"MEDIUM",explanation:x.explanation,remediation:x.remediation
  }));
  if(offlineFindings.some(x=>!VALID_HEX.test(x.fingerprint)||!x.ruleId.startsWith("API03_")))
   throw new Error("VAPT11_OFFLINE_FINDING_INTEGRITY_INVALID");
  const ptObs:SyntheticObservation[]=(ptReport?.observations??[]).map(x=>({
   ruleId:x.ruleId,revision:x.revision,fingerprint:x.fingerprint,code:x.code,
   impact:x.impact??getRule(x.ruleId)?.impact??"LOW",
   confidence:x.confidence??"MEDIUM",remediation:x.remediation??getRule(x.ruleId)?.remediation??""
  }));
  const ruleOps:Record<string,string>={};
  for(const e of (phase9?.plan as OrchestrationPlan|undefined)?.evaluations??[]){
   if(ruleOps[e.ruleId]&&ruleOps[e.ruleId]!==e.operationKey)
    throw new Error("VAPT11_RULE_OPERATION_AMBIGUOUS");
   ruleOps[e.ruleId]=e.operationKey;
  }
  const correlated=correlateAutonomousVaptEvidence({
   tenantId:tenant,targetId:v.target_id,specFingerprint:plan.specFingerprint,
   fixtureId:plan.fixtureId,fixtureVersion:plan.fixtureVersion,profile:plan.ptProfile,
   ptRuleOperations:ruleOps},offlineFindings,ptObs);
  for(const obs of correlated.observations)await tx.query(
   "INSERT INTO api_vapt11_correlations(id,tenant_id,parent_assessment_id,stable_key,source,projection) VALUES($1,$2,$3,$4,$5,$6::jsonb)",
   [uuid(),tenant,id,obs.key,obs.source,JSON.stringify(obs)]);
  for(const r of correlated.relationships)await tx.query(
   "INSERT INTO api_vapt11_correlations(id,tenant_id,parent_assessment_id,stable_key,source,projection) VALUES($1,$2,$3,$4,'RELATED_EVIDENCE',$5::jsonb)",
   [uuid(),tenant,id,r.key,JSON.stringify(r)]);
  const report={schemaVersion:AUTONOMOUS_VAPT_REPORT,assessmentId:id,status:"COMPLETED",
   mode:plan.mode,product:"ISOLATED SYNTHETIC AUTONOMOUS API VAPT",
   fullAuthorizedVaptCompleted:plan.mode==="GOVERNED_SYNTHETIC",
   targetId:plan.targetId,tenantId:tenant,specificationId:plan.specificationId,
   specificationVersion:plan.specificationVersion,specFingerprint:plan.specFingerprint,
   inventoryFingerprint:plan.inventoryFingerprint,engineVersion:plan.engineVersion,
   scopeRevision:plan.targetScopeRevision,planFingerprint:v.fingerprint,
   offlineAssessmentId:v.offline_assessment_id,ptAssessmentId:v.pt_assessment_id,
   offlineEngine:plan.offlineEngine,ptPolicy:plan.ptPolicyId,
   fixtureId:plan.fixtureId,fixtureVersion:plan.fixtureVersion,fixtureProfile:plan.ptProfile,
   permitFingerprint:plan.permitFingerprint,stageDefinitions:plan.stages,
   components:children.rows.map(x=>({id:x.id,engine:x.engine_version,status:x.status})),
   inventory:{operationsImported:plan.operations.length,operations:plan.operations,
    supportedRuntimeOperations:plan.operations.filter(x=>x.method==="GET").length},
   offline:{report:offlineReport,findings:offlineFindings,
    analysisCoverage:offlineReport.coverage??[],operationsAnalyzed:offlineReport.operationsAssessed??0},
   pt:{report:ptReport,selectedRules:plan.rules,plannedEvaluations:plan.plannedEvaluations,
    executedEvaluations:ptReport?.accounting?.executed??0,
    secureNegativeChecks:ptReport?.coverage?.passed??0,
    syntheticObservations:ptObs.length},
   findings:correlated.observations,relationships:correlated.relationships,
   coverage:{offlineOperations:offlineReport.operationsAssessed??0,
    importedOperations:plan.operations.length,
    ptRulesSelected:plan.rules.length,
    ptRulesExecuted:ptReport?.coverage?.rulesExecuted??0,
    ptEvaluationsPlanned:plan.plannedEvaluations,
    ptEvaluationsExecuted:ptReport?.accounting?.executed??0,
    ptNotTested:plan.mode==="OFFLINE_ONLY",
    requiredStages:plan.stages.length,completedStages:plan.stages.length},
   lineageParentId:v.lineage_parent_id??null,syntheticOnly:true,customerNetworkRequests:0,
   customerRuntimeVerified:false,verifiedFixed:false,confirmedCustomerVulnerabilities:[],
   limitations:["NOT AUTHORIZED FOR LIVE CUSTOMER API TESTING",
    "NO CUSTOMER VULNERABILITY IS CONFIRMED BY SYNTHETIC FIXTURES",
    "REAL HOST AUTHORIZATION UNAVAILABLE",
    "NO EVIDENCE != SAFE","UNKNOWN != SAFE","NO LONGER OBSERVED != VERIFIED_FIXED",
    ...(plan.mode==="OFFLINE_ONLY"?["SPEC_ONLY is not a completed governed runtime PT"]:[])]};
  const reportFingerprint=planFingerprint(report);
  await tx.query("INSERT INTO api_vapt11_reports(id,tenant_id,parent_assessment_id,projection,fingerprint) VALUES($1,$2,$3,$4::jsonb,$5)",
   [uuid(),tenant,id,JSON.stringify(report),reportFingerprint]);
  await tx.query("UPDATE api_assessments SET status='COMPLETED',completed_at=now() WHERE id=$1 AND status='PROCESSING'",[id]);
  await tx.query("INSERT INTO api_vapt11_events(id,tenant_id,parent_assessment_id,code,details) VALUES($1,$2,$3,'PARENT_COMPLETED',$4::jsonb)",
   [uuid(),tenant,id,JSON.stringify({reportFingerprint,offlineFindings:offlineFindings.length,
    syntheticObservations:ptObs.length,relationships:correlated.relationships.length})]);
  await tx.query("DELETE FROM api_queue.api_assessment_queue WHERE assessment_id=$1 AND claim_token=$2",[id,token]);
 });
}
