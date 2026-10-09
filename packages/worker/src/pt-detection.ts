import {withWorkerTenant,uuid} from "../../database/src/index.js";
import {DETECTION_ENGINE,DETECTION_FIXTURE,type Evidence,type Profile} from "../../pt/src/security-fixture.js";
import {RULES,evaluateRule,getRule,planFingerprint,type RuleId} from "../../pt/src/detection.js";
import {governedPtDetectionInteraction,settlePtDetectionReservations,withGovernedPtDetectionPublication,
 type DetectionEvaluationInput} from "./pt.js";

type PlanRule={id:RuleId;revision:string};
type PlanEval=DetectionEvaluationInput&{ruleId:RuleId;caseId:string};
type Snapshot={assessment_id:string;tenant_id:string;fixture_version:number;fixture_profile:Profile;
 engine_version:string;rules:PlanRule[];evaluations:PlanEval[];plan_fingerprint:string;
 scope_id:string;fixture_id:string;spec_fingerprint:string;operation_keys:string[];
 specification_id:string};
function validatePlan(s:Snapshot,operations:readonly {operation_key:string;method:string;path:string}[]):void{
 if(s.engine_version!==DETECTION_ENGINE||s.fixture_id!==DETECTION_FIXTURE||s.fixture_version!==1||
  s.rules.length<1||s.rules.length>RULES.length||s.evaluations.length<1||s.evaluations.length>20)
  throw new Error("DETECTION_SNAPSHOT_UNSUPPORTED");
 const snapshot={engineVersion:DETECTION_ENGINE,fixtureVersion:1,fixtureId:DETECTION_FIXTURE,
  profile:s.fixture_profile,rules:s.rules,evaluations:s.evaluations,
  specFingerprint:s.spec_fingerprint,scopeId:s.scope_id};
 if(planFingerprint(snapshot)!==s.plan_fingerprint)throw new Error("DETECTION_SNAPSHOT_FINGERPRINT_MISMATCH");
 const expected:PlanEval[]=[];
 const ids=new Set<string>();
 for(const selected of s.rules){
  const rule=getRule(selected.id);
  if(!rule||selected.revision!==rule.revision||ids.has(rule.id))throw new Error("DETECTION_RULE_REVISION_MISMATCH");
  ids.add(rule.id);
  const operation=operations.find(x=>x.path===rule.path&&x.method==="GET"&&s.operation_keys.includes(x.operation_key));
  if(!operation)throw new Error("DETECTION_PLAN_OUT_OF_SCOPE");
  for(const c of rule.cases)expected.push({
   evaluationKey:rule.id+":"+c.caseId,ruleId:rule.id,caseId:c.caseId,
   operationKey:operation.operation_key,path:c.path,actor:c.actor,method:"GET",profile:s.fixture_profile
  });
 }
 if(expected.length!==s.evaluations.length)throw new Error("DETECTION_PLAN_EVALUATION_MISMATCH");
 // Profile is a plan-level immutable value. The worker supplies it, not the browser.
 for(let i=0;i<expected.length;i++){
  const a=expected[i]!,b=s.evaluations[i]!;
  if(a.evaluationKey!==b.evaluationKey||a.ruleId!==b.ruleId||a.caseId!==b.caseId||
   a.operationKey!==b.operationKey||a.path!==b.path||a.method!==b.method||a.actor!==b.actor)
   throw new Error("DETECTION_PLAN_EVALUATION_MISMATCH");
 }
}
async function fail(tenant:string,id:string,token:string,code:string):Promise<void>{
 await settlePtDetectionReservations(tenant,id);
 await withWorkerTenant(tenant,async tx=>{
  const q=await tx.query("SELECT claim_token FROM api_queue.api_assessment_queue WHERE assessment_id=$1 FOR UPDATE",[id]);
  if(q.rows[0]?.claim_token!==token)return;
  await tx.query("UPDATE api_assessments SET status='FAILED',error_code=$2,completed_at=now() WHERE id=$1 AND status='PROCESSING'",[id,code]);
  await tx.query("INSERT INTO api_pt_events(id,tenant_id,subject_id,action,details) VALUES($1,$2,$3,'PT7_DETECTION_FAILED',$4::jsonb)",
   [uuid(),tenant,id,JSON.stringify({code})]);
  await tx.query("DELETE FROM api_queue.api_assessment_queue WHERE assessment_id=$1 AND claim_token=$2",[id,token]);
 });
}
export async function processPtDetectionJob(tenant:string,id:string,token:string):Promise<void>{
 let failed=false;
 try{
  const data=await withWorkerTenant(tenant,async tx=>{
   const r=await tx.query("SELECT p.*,j.scope_id,j.operation_keys,s.fixture_id,s.spec_fingerprint,s.specification_id FROM api_pt_detection_plans p JOIN api_pt_jobs j ON j.assessment_id=p.assessment_id AND j.tenant_id=p.tenant_id JOIN api_pt_scopes s ON s.id=j.scope_id AND s.tenant_id=j.tenant_id WHERE p.assessment_id=$1",[id]);
   if(!r.rowCount)throw new Error("DETECTION_PLAN_MISSING");
   const snapshot=r.rows[0] as Snapshot;
   const ops=await tx.query("SELECT operation_key,method,path FROM api_inventory_operations WHERE specification_id=$1",[snapshot.specification_id]);
   return {snapshot,operations:ops.rows as {operation_key:string;method:string;path:string}[]};
  });
  validatePlan(data.snapshot,data.operations);
  for(const planned of data.snapshot.evaluations){
   const input:DetectionEvaluationInput={evaluationKey:planned.evaluationKey,operationKey:planned.operationKey,
    method:planned.method,path:planned.path,actor:planned.actor,profile:data.snapshot.fixture_profile};
   const result=await governedPtDetectionInteraction(tenant,id,token,input);
   if(result.status!=="CONSUMED"){failed=true;break;}
  }
  if(failed){await fail(tenant,id,token,"PT7_INCOMPLETE_OR_DENIED");return;}
  const finalized=await withGovernedPtDetectionPublication(tenant,id,token,async tx=>{
   const q=await tx.query("SELECT evaluation_key,state,evidence FROM api_pt_detection_evaluations WHERE assessment_id=$1 ORDER BY evaluation_key",[id]);
   const lookup=new Map((q.rows as {evaluation_key:string;state:string;evidence:Evidence|null}[])
    .map(x=>[x.evaluation_key,x]));
   if(lookup.size!==data.snapshot.evaluations.length||[...lookup.values()].some(x=>x.state!=="CONSUMED"||!x.evidence))
    throw new Error("PT7_MISSING_COMPLETED_EVALUATIONS");
   const results=data.snapshot.rules.map(selected=>{
    const rule=getRule(selected.id);
    if(!rule||rule.revision!==selected.revision)throw new Error("PT7_RULE_REVISION_CHANGED");
    const evidence=rule.cases.map(testCase=>lookup.get(rule.id+":"+testCase.caseId)?.evidence??null);
    if(evidence.some(x=>x===null))throw new Error("PT7_MISSING_EVIDENCE");
    return evaluateRule(rule,data.snapshot.fixture_profile,evidence as Evidence[]);
   });
   if(results.some(x=>x.status==="INCONCLUSIVE"||x.status==="SKIPPED"))
    throw new Error("PT7_INCOMPLETE_ASSERTION_EVIDENCE");
   for(const x of results){
    await tx.query("INSERT INTO api_pt_detection_results(id,tenant_id,assessment_id,rule_id,rule_revision,status,code,fingerprint,evidence) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb)",
     [uuid(),tenant,id,x.ruleId,x.revision,x.status,x.code,x.fingerprint,JSON.stringify(x.evidence)]);
   }
   const findings=results.filter(x=>x.status==="OBSERVED");
   const report={
    schemaVersion:"pt-detection-report-v1",assessmentId:id,scopeId:data.snapshot.scope_id,
    fixtureId:DETECTION_FIXTURE,fixtureVersion:1,profile:data.snapshot.fixture_profile,
    engineVersion:DETECTION_ENGINE,ruleCatalogVersion:"1.0.0",planFingerprint:data.snapshot.plan_fingerprint,
    specificationFingerprint:data.snapshot.spec_fingerprint,validationLevel:"SYNTHETIC_PT_OBSERVATION",
    status:"COMPLETED",coverage:{requested:results.length,executed:results.length,passed:results.length-findings.length,
     observed:findings.length,skipped:0,inconclusive:0,actualEvaluations:lookup.size},
    observations:findings,ruleResults:results.map(x=>({ruleId:x.ruleId,status:x.status,code:x.code,fingerprint:x.fingerprint})),
    customerNetworkRequests:0,syntheticOnly:true,realHostAuthorization:false,runtimeCustomerVerification:false,
    confirmedCustomerVulnerabilities:[],verifiedFixed:false,
    limitations:["ISOLATED SYNTHETIC API PENETRATION TESTING — NOT CUSTOMER PRODUCTION VULNERABILITY VERIFICATION",
     "Synthetic fixture policy demonstrates only test-case behavior","No live customer API or customer data was accessed",
     "Missing evidence does not imply safety","Disappeared synthetic findings do not establish VERIFIED_FIXED"]
   };
   await tx.query("INSERT INTO api_pt_detection_reports(id,tenant_id,assessment_id,projection) VALUES($1,$2,$3,$4::jsonb)",
    [uuid(),tenant,id,JSON.stringify(report)]);
   await tx.query("UPDATE api_assessments SET status='COMPLETED',completed_at=now() WHERE id=$1 AND status='PROCESSING'",[id]);
   await tx.query("INSERT INTO api_pt_events(id,tenant_id,subject_id,action,details) VALUES($1,$2,$3,'PT7_DETECTION_COMPLETED',$4::jsonb)",
    [uuid(),tenant,id,JSON.stringify({observations:findings.length,evaluations:lookup.size})]);
   await tx.query("DELETE FROM api_queue.api_assessment_queue WHERE assessment_id=$1 AND claim_token=$2",[id,token]);
   return true;
  });
  if(!finalized){await fail(tenant,id,token,"PT7_PUBLICATION_AUTHORITY_LOST");}
 }catch{
  await fail(tenant,id,token,"PT7_WORKER_OR_PUBLICATION_FAILURE");
 }
}
