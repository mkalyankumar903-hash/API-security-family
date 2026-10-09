/** Phase09 synthetic-only API facade; signed claims are validated, not issued here. */
import type {FastifyInstance,FastifyRequest} from "fastify";
import type {PoolClient} from "pg";
import {withTenant,uuid} from "../../database/src/index.js";
import {enforcePermit,verifyStoredTestPermit,type PtClaims} from "../../pt/src/permit.js";
import {DETECTION_FIXTURE} from "../../pt/src/security-fixture.js";
import {planFingerprint} from "../../pt/src/detection.js";
import {POLICIES,ORCHESTRATOR_ENGINE,buildOrchestrationPlan,orchestrationFingerprint,
 OrchestratorPlanError,type Binding,type Operation} from "../../pt/src/orchestrator.js";
import {persistTerminalCoverage} from "../../pt/src/terminal-coverage.js";
import {PtError} from "./pt.js";
import {persistOrchestrationTerminal} from "../../pt/src/orchestration-terminal.js";

const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const id=(v:unknown)=>{if(typeof v!=="string"||!UUID.test(v))throw new PtError(400,"INVALID_ID");return v;};
const param=(r:FastifyRequest,k="id")=>id((r.params as Record<string,unknown>)[k]);
const headerKey=(r:FastifyRequest)=>{
 const k=r.headers["idempotency-key"];
 if(typeof k!=="string"||!/^[a-zA-Z0-9:_-]{8,128}$/.test(k))throw new PtError(400,"IDEMPOTENCY_KEY_REQUIRED");
 return k;
};
const body=(input:unknown)=>{
 if(!input||typeof input!=="object"||Array.isArray(input))throw new PtError(400,"INVALID_BODY");
 const b=input as Record<string,unknown>;
 if(Object.keys(b).some(k=>!["policyId","profile"].includes(k))||
  typeof b.policyId!=="string"||typeof b.profile!=="string")throw new PtError(400,"INVALID_ORCHESTRATION_REQUEST");
 return {policyId:b.policyId,profile:b.profile};
};
type Scope={
 id:string;tenant_id:string;target_id:string;specification_id:string;specification_version:number;
 spec_fingerprint:string;target_verification_version:number;target_scope_revision:number;
 environment:string;fixture_id:string;operation_keys:string[];exclusions:string[];
 max_evaluations:number;rate_per_minute:number;max_concurrency:number;deadline_ms:number;
};
type Permit={id:string;claims:PtClaims;token_hash:string;signed_body:string;revoked_at:string|null;
 expires_at:string;consumed:number;reserved:number;rate_used:number;rate_start:string};
type Current={lifecycle:string;environment:string;verification_version:number;scope_revision:number};
async function context(tx:PoolClient,sid:string,lock=false){
 const scope=await tx.query("SELECT * FROM api_pt_scopes WHERE id=$1",[sid]);
 if(!scope.rowCount)throw new PtError(404,"SCOPE_NOT_FOUND");
 const s=scope.rows[0] as Scope;
 if(s.fixture_id!==DETECTION_FIXTURE)throw new PtError(409,"TRUSTED_DETECTION_FIXTURE_REQUIRED");
 const t=await tx.query("SELECT lifecycle,environment,verification_version,scope_revision FROM api_targets WHERE id=$1"+(lock?" FOR UPDATE":""),[s.target_id]);
 if(!t.rowCount)throw new PtError(404,"TARGET_NOT_FOUND");
 const p=await tx.query("SELECT id,claims,token_hash,signed_body,revoked_at,expires_at,consumed,reserved,rate_used,rate_start FROM api_pt_permits WHERE scope_id=$1"+(lock?" FOR UPDATE":""),[sid]);
 const ops=await tx.query("SELECT operation_key,method,path FROM api_inventory_operations WHERE specification_id=$1 AND method='GET'",[s.specification_id]);
 return {s,current:t.rows[0] as Current,permit:p.rows[0] as Permit|undefined,
  operations:ops.rows as Operation[]};
}
function binding(tenant:string,s:Scope,p?:Permit):Binding{
 return {tenantId:tenant,targetId:s.target_id,environment:"SYNTHETIC",specificationId:s.specification_id,
  specificationVersion:s.specification_version,specFingerprint:s.spec_fingerprint,
  targetVerificationVersion:s.target_verification_version,targetScopeRevision:s.target_scope_revision,
  scopeId:s.id,fixtureId:s.fixture_id,
  permitId:p?.id??"00000000-0000-4000-8000-000000000000",
  permitFingerprint:p?.token_hash??"0".repeat(64),operationKeys:s.operation_keys,exclusions:s.exclusions,
  maxEvaluations:s.max_evaluations,ratePerMinute:s.rate_per_minute,
  maxConcurrency:s.max_concurrency,deadlineMs:s.deadline_ms};
}
function makePlan(policyId:string,profile:string,tenant:string,s:Scope,p:Permit|undefined,ops:Operation[]){
 try{return buildOrchestrationPlan(policyId,profile,binding(tenant,s,p),ops);}
 catch(e){if(e instanceof OrchestratorPlanError)throw new PtError(409,e.code);throw e;}
}
function checkPermit(tenant:string,s:Scope,current:Current,p?:Permit):string|null{
 if(current.lifecycle!=="ACTIVE"||current.environment!=="SYNTHETIC")return "TARGET_NOT_SYNTHETIC_ACTIVE";
 if(current.verification_version!==s.target_verification_version||
  current.scope_revision!==s.target_scope_revision)return "TARGET_SCOPE_CHANGED";
 if(!p)return "AUTHORIZATION_MISSING";
 if(p.revoked_at)return "PERMIT_REVOKED";
 if(new Date(p.expires_at).getTime()<=Date.now())return "PERMIT_EXPIRED";
 try{
  const c=verifyStoredTestPermit(p.claims,p.token_hash,p.signed_body);
  if(c.permitId!==p.id)throw new Error("PERMIT_ID_MISMATCH");
  enforcePermit(c,{tenantId:tenant,targetId:s.target_id,scopeId:s.id,
   specificationId:s.specification_id,specificationVersion:s.specification_version,
   specFingerprint:s.spec_fingerprint,targetVerificationVersion:current.verification_version,
   targetScopeRevision:current.scope_revision,fixtureId:s.fixture_id});
  if(c.maxEvaluations!==s.max_evaluations||c.maxConcurrency!==s.max_concurrency||
   c.ratePerMinute!==s.rate_per_minute||c.deadlineMs!==s.deadline_ms||
   JSON.stringify(c.operationKeys)!==JSON.stringify(s.operation_keys)||
   JSON.stringify(c.exclusions)!==JSON.stringify(s.exclusions))return "PERMIT_POLICY_MISMATCH";
  return null;
 }catch{return "PERMIT_INTEGRITY_INVALID";}
}
async function stopped(tx:PoolClient,tenant:string,lock=false):Promise<boolean>{
 await tx.query("INSERT INTO api_pt_stop(tenant_id) VALUES($1) ON CONFLICT DO NOTHING",[tenant]);
 const r=await tx.query("SELECT enabled FROM api_pt_stop WHERE tenant_id=$1"+(lock?" FOR UPDATE":""),[tenant]);
 return r.rows[0]?.enabled===true;
}
export function registerOrchestratorRoutes(app:FastifyInstance,identity:(req:FastifyRequest)=>string):void{
 app.get("/v9/pt/policies",async()=>({engineVersion:ORCHESTRATOR_ENGINE,syntheticOnly:true,
  customerNetworkRequests:0,profiles:Object.entries(POLICIES).map(([id,v])=>({
   id,version:v.version,ruleIds:v.ids
  })),realHostAuthorization:"UNAVAILABLE"}));
 app.get("/v9/pt/scopes/:id/preview",async req=>{
  const tenant=identity(req),sid=param(req),q=(req.query??{}) as Record<string,unknown>;
  if(Object.keys(q).some(k=>!["policyId","profile"].includes(k))||
    typeof q.policyId!=="string"||typeof q.profile!=="string")throw new PtError(400,"INVALID_PREVIEW_QUERY");
  return withTenant(tenant,async tx=>{
   const {s,current,permit:p,operations}=await context(tx,sid);
   const plan=makePlan(q.policyId as string,q.profile as string,tenant,s,p,operations);
   const reason=await stopped(tx,tenant)?"EMERGENCY_STOP_ACTIVE":checkPermit(tenant,s,current,p);
   return {plan,planFingerprint:orchestrationFingerprint(plan),authorizationReady:reason===null,
    denialCode:reason,remainingPermitEvaluations:p?p.claims.maxEvaluations-p.consumed-p.reserved:0,
    executable:reason===null&&!!p&&plan.maxEvaluations<=p.claims.maxEvaluations-p.consumed-p.reserved,
    notice:"ISOLATED SYNTHETIC AUTONOMOUS API PT — NOT AUTHORIZED FOR LIVE CUSTOMER API TESTING"};
  });
 });
 app.post("/v9/pt/scopes/:id/orchestrations",async(req,reply)=>{
  const tenant=identity(req),sid=param(req),b=body(req.body),idem=headerKey(req),jobId=uuid();
  const result=await withTenant(tenant,async tx=>{
   // Serialize duplicate admission and emergency stop using the accepted Phase06 stop row.
   const isStopped=await stopped(tx,tenant,true);
   const {s,current,permit:p,operations}=await context(tx,sid,true);
   const plan=makePlan(b.policyId,b.profile,tenant,s,p,operations);
   const fingerprint=orchestrationFingerprint(plan);
   const existing=await tx.query("SELECT a.id,o.fingerprint FROM api_assessments a JOIN api_pt9_plans o ON o.assessment_id=a.id AND o.tenant_id=a.tenant_id WHERE a.tenant_id=$1 AND a.idempotency_key=$2",[tenant,idem]);
   if(existing.rowCount){
    if(existing.rows[0].fingerprint!==fingerprint)throw new PtError(409,"IDEMPOTENCY_CONFLICT");
    return {id:existing.rows[0].id,created:false,planFingerprint:fingerprint};
   }
   if(isStopped)throw new PtError(409,"EMERGENCY_STOP_ACTIVE");
   const reason=checkPermit(tenant,s,current,p);
   if(reason)throw new PtError(409,reason);
   if(!p)throw new PtError(409,"AUTHORIZATION_MISSING");
   if(plan.maxEvaluations>p.claims.maxEvaluations-p.consumed-p.reserved)
    throw new PtError(409,"PERMIT_BUDGET_EXHAUSTED");
   if(plan.maxEvaluations>s.rate_per_minute)throw new PtError(409,"RATE_LIMIT_TOO_SMALL");
   const active=await tx.query("SELECT count(*)::int AS tenant_active,count(*) FILTER(WHERE j.target_id=$1)::int AS target_active,count(*) FILTER(WHERE j.permit_id=$2)::int AS permit_active FROM api_pt_jobs j JOIN api_assessments a ON a.id=j.assessment_id WHERE j.tenant_id=$3 AND a.status IN('QUEUED','PROCESSING')",[s.target_id,p.id,tenant]);
   if(active.rows[0].tenant_active>=3||active.rows[0].target_active>=2||
    active.rows[0].permit_active>=s.max_concurrency)throw new PtError(409,"CONCURRENCY_LIMIT");
   const operationsUsed=[...new Set(plan.evaluations.map(x=>x.operationKey))];
   await tx.query("INSERT INTO api_assessments(id,tenant_id,target_id,specification_id,status,mode,idempotency_key,engine_version,inventory_version,inventory_raw_fingerprint,inventory_fingerprint) SELECT $1,$2,$3,$4,'QUEUED','SYNTHETIC_PT_FIXTURE',$5,$6,i.version_number,i.raw_fingerprint,i.normalized_fingerprint FROM api_spec_inventories i WHERE i.specification_id=$4",
    [jobId,tenant,s.target_id,s.specification_id,idem,ORCHESTRATOR_ENGINE]);
   await tx.query("INSERT INTO api_pt_jobs(assessment_id,tenant_id,target_id,scope_id,permit_id,operation_keys,job_deadline) VALUES($1,$2,$3,$4,$5,$6::jsonb,now()+($7::text||' milliseconds')::interval)",
    [jobId,tenant,s.target_id,s.id,p.id,JSON.stringify(operationsUsed),s.deadline_ms]);
   // Reuse Phase07 authoritative evaluation ledger (foreign keyed to an immutable detection subplan).
   const detectionPlan={engineVersion:"pt-detection-v1",fixtureVersion:1,fixtureId:DETECTION_FIXTURE,
    profile:plan.profile,rules:plan.rules,evaluations:plan.evaluations,
    specFingerprint:s.spec_fingerprint,scopeId:s.id};
   await tx.query("INSERT INTO api_pt_detection_plans(assessment_id,tenant_id,fixture_version,fixture_profile,engine_version,rules,evaluations,plan_fingerprint) VALUES($1,$2,1,$3,'pt-detection-v1',$4::jsonb,$5::jsonb,$6)",
    [jobId,tenant,plan.profile,JSON.stringify(plan.rules),JSON.stringify(plan.evaluations),planFingerprint(detectionPlan)]);
   await tx.query("INSERT INTO api_pt9_plans(assessment_id,tenant_id,policy_id,policy_version,plan,fingerprint) VALUES($1,$2,$3,$4,$5::jsonb,$6)",
    [jobId,tenant,plan.policyId,plan.policyVersion,JSON.stringify(plan),fingerprint]);
   for(const [ordinal,stage] of plan.stages.entries()){
    await tx.query("INSERT INTO api_pt9_stages(id,tenant_id,assessment_id,stage_id,stage_type,ordinal,dependencies,evaluation_keys,planned) VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,$8::jsonb,$9)",
     [uuid(),tenant,jobId,stage.id,stage.type,ordinal,JSON.stringify(stage.dependencies),JSON.stringify(stage.evaluationKeys),stage.budget]);
   }
   await tx.query("SELECT public.api_enqueue_assessment($1)",[jobId]);
   await tx.query("INSERT INTO api_pt_events(id,tenant_id,subject_id,action,details) VALUES($1,$2,$3,'PT9_ORCHESTRATION_QUEUED',$4::jsonb)",
    [uuid(),tenant,jobId,JSON.stringify({fingerprint,policyId:plan.policyId,planned:plan.maxEvaluations})]);
   return {id:jobId,created:true,status:"QUEUED",planFingerprint:fingerprint,
    stages:plan.stages.length,plannedEvaluations:plan.maxEvaluations,customerNetworkRequests:0};
  });
  reply.code(result.created?201:200).send(result);
 });
 app.get("/v9/pt/orchestrations/:id",async req=>{
  const tenant=identity(req),jid=param(req);
  return withTenant(tenant,async tx=>{
   const p=await tx.query("SELECT p.plan,p.fingerprint,a.status,a.error_code,a.created_at,a.completed_at FROM api_pt9_plans p JOIN api_assessments a ON a.id=p.assessment_id AND a.tenant_id=p.tenant_id WHERE p.assessment_id=$1",[jid]);
   if(!p.rowCount)throw new PtError(404,"ORCHESTRATION_NOT_FOUND");
   const stages=await tx.query("SELECT stage_id,stage_type,ordinal,dependencies,planned,status,reason,evidence_fingerprint,started_at,finished_at FROM api_pt9_stages WHERE assessment_id=$1 ORDER BY ordinal",[jid]);
   const counts=await tx.query("SELECT state,count(*)::int AS count FROM api_pt_detection_evaluations WHERE assessment_id=$1 GROUP BY state",[jid]);
   return {id:jid,...p.rows[0],stages:stages.rows,accounting:Object.fromEntries(counts.rows.map(x=>[x.state,x.count])),
    customerNetworkRequests:0,customerRuntimeVerified:false,verifiedFixed:false};
  });
 });
 app.get("/v9/pt/orchestrations/:id/decisions",async req=>{
  const t=identity(req),jid=param(req);
  return withTenant(t,async tx=>(await tx.query("SELECT stage_id,code,details,created_at FROM api_pt9_decisions WHERE assessment_id=$1 ORDER BY created_at,id LIMIT 100",[jid])).rows);
 });
 app.get("/v9/pt/orchestrations/:id/report",async req=>{
  const t=identity(req),jid=param(req);
  return withTenant(t,async tx=>{
   const r=await tx.query("SELECT projection FROM api_pt9_reports WHERE assessment_id=$1",[jid]);
   if(!r.rowCount)throw new PtError(409,"ORCHESTRATION_REPORT_NOT_READY");
   return r.rows[0].projection;
  });
 });
 app.get("/v9/pt/orchestrations/:id/terminal",async req=>{
  const t=identity(req),jid=param(req);
  return withTenant(t,async tx=>{
   const r=await tx.query("SELECT projection FROM api_pt9_terminal WHERE assessment_id=$1",[jid]);
   if(!r.rowCount)throw new PtError(409,"ORCHESTRATION_TERMINAL_NOT_READY");
   return r.rows[0].projection;
  });
 });
 app.get("/v9/pt/orchestrations/:id/export",async(req,reply)=>{
  const t=identity(req),jid=param(req);
  const report=await withTenant(t,async tx=>{
   const r=await tx.query("SELECT projection FROM api_pt9_reports WHERE assessment_id=$1",[jid]);
   if(!r.rowCount)throw new PtError(409,"ORCHESTRATION_REPORT_NOT_READY");
   return r.rows[0].projection;
  });
  reply.header("content-disposition","attachment; filename=synthetic-orchestration-"+jid+".json").type("application/json").send(report);
 });
 app.get("/v9/pt/targets/:id/history",async req=>{
  const t=identity(req),tid=param(req),q=(req.query??{}) as Record<string,unknown>;
  const limit=q.limit===undefined?30:Number(q.limit);
  if(!Number.isInteger(limit)||limit<1||limit>50)throw new PtError(400,"INVALID_HISTORY_LIMIT");
  return withTenant(t,async tx=>(await tx.query("SELECT a.id,a.status,a.error_code,o.policy_id,o.fingerprint,a.created_at,a.completed_at FROM api_pt9_plans o JOIN api_pt_jobs j ON j.assessment_id=o.assessment_id JOIN api_assessments a ON a.id=o.assessment_id WHERE j.target_id=$1 ORDER BY a.created_at DESC,a.id LIMIT $2",[tid,limit])).rows);
 });
 app.get("/v9/pt/orchestrations/:id/compare/:otherId",async req=>{
  const t=identity(req),first=param(req),second=param(req,"otherId");
  if(first===second)throw new PtError(409,"SAME_RUN_COMPARISON_INVALID");
  return withTenant(t,async tx=>{
   const rows=await tx.query("SELECT p.assessment_id,p.plan,r.projection FROM api_pt9_plans p JOIN api_pt9_reports r ON r.assessment_id=p.assessment_id AND r.tenant_id=p.tenant_id WHERE p.assessment_id=ANY($1::uuid[])",[[first,second]]);
   if(rows.rowCount!==2)throw new PtError(409,"COMPARISON_REQUIRES_COMPLETED_REPORTS");
   const a=rows.rows.find(x=>x.assessment_id===first),b=rows.rows.find(x=>x.assessment_id===second);
   const x=a.plan,y=b.plan;
   if(x.binding.targetId!==y.binding.targetId||x.binding.specFingerprint!==y.binding.specFingerprint||
    x.policyId!==y.policyId||x.policyVersion!==y.policyVersion||x.fixtureVersion!==y.fixtureVersion||
    x.profile!==y.profile||JSON.stringify(x.rules)!==JSON.stringify(y.rules))
    return {compatibility:"INCOMPATIBLE",verifiedFixed:false,customerNetworkRequests:0};
   const before=new Set((a.projection.observations as {ruleId:string}[]).map(x=>x.ruleId));
   const after=new Set((b.projection.observations as {ruleId:string}[]).map(x=>x.ruleId));
   return {compatibility:"COMPATIBLE",newlyObserved:[...after].filter(v=>!before.has(v)),
    noLongerObserved:[...before].filter(v=>!after.has(v)),
    stillObserved:[...after].filter(v=>before.has(v)),verifiedFixed:false,
    customerNetworkRequests:0,limitation:"Disappeared synthetic observations are not VERIFIED_FIXED"};
  });
 });
 app.post("/v9/pt/orchestrations/:id/cancel",async req=>{
  const t=identity(req),jid=param(req);
  return withTenant(t,async tx=>{
   const found=await tx.query("SELECT 1 FROM api_pt9_plans WHERE assessment_id=$1",[jid]);
   if(!found.rowCount)throw new PtError(404,"ORCHESTRATION_NOT_FOUND");
   const result=await tx.query("SELECT public.api_cancel_assessment($1) AS cancelled",[jid]);
   if(!result.rows[0]?.cancelled)throw new PtError(409,"ORCHESTRATION_NOT_CANCELLABLE");
   await tx.query("UPDATE api_pt9_stages SET status='CANCELLED',reason='CUSTOMER_CANCELLED',finished_at=now() WHERE assessment_id=$1 AND status IN('PENDING','RUNNING')",[jid]);
   await persistTerminalCoverage(tx,t,jid);
   await persistOrchestrationTerminal(tx,t,jid,"CANCELLED","CUSTOMER_CANCELLED");
   return {id:jid,status:"CANCELLED",customerNetworkRequests:0};
  });
 });
}
