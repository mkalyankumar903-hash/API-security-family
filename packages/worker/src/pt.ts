import type {PoolClient} from "pg";
import {withWorkerTenant,uuid} from "../../database/src/index.js";
import {verifyTestPermit,enforcePermit,digest,PermitError,type PtClaims} from "../../pt/src/permit.js";
import {evaluateFixture,fixtureOperation,FIXTURE_ID} from "../../pt/src/fixture.js";

type State={
 scope_id:string;permit_id:string;target_id:string;specification_id:string;specification_version:number;
 spec_fingerprint:string;target_verification_version:number;target_scope_revision:number;
 fixture_id:string;operation_keys:string[];exclusions:string[];max_evaluations:number;
 rate_per_minute:number;max_concurrency:number;deadline_ms:number;job_deadline:Date|string;
 signed_token:string;token_hash:string;revoked_at:string|null;expires_at:string;
 consumed:number;reserved:number;rate_start:string;rate_used:number;
 target_environment:string;target_lifecycle:string;current_verification:number;current_scope_revision:number;
};
type Op={operation_key:string;method:string;path:string};
type Admission={decision:"RESERVED"|"DENIED"|"SKIPPED"|"LEASE_LOST";code:string;op:Op};
const empty=(key:string):Op=>({operation_key:key,method:"UNKNOWN",path:""});
async function context(tx:PoolClient,tenant:string,id:string,lock:boolean):Promise<State|null>{
 const r=await tx.query(
  "SELECT j.scope_id,j.permit_id,j.target_id,s.specification_id,s.specification_version,s.spec_fingerprint,s.target_verification_version,s.target_scope_revision,s.fixture_id,s.operation_keys AS allowed_keys,s.exclusions,s.max_evaluations,s.rate_per_minute,s.max_concurrency,s.deadline_ms,j.operation_keys,j.job_deadline,p.signed_token,p.token_hash,p.revoked_at,p.expires_at,p.consumed,p.reserved,p.rate_start,p.rate_used,t.environment AS target_environment,t.lifecycle AS target_lifecycle,t.verification_version AS current_verification,t.scope_revision AS current_scope_revision FROM api_pt_jobs j JOIN api_pt_scopes s ON s.id=j.scope_id AND s.tenant_id=j.tenant_id JOIN api_pt_permits p ON p.id=j.permit_id AND p.tenant_id=j.tenant_id JOIN api_targets t ON t.id=j.target_id AND t.tenant_id=j.tenant_id WHERE j.tenant_id=$1 AND j.assessment_id=$2"+(lock?" FOR UPDATE OF p,j,t":""),[tenant,id]);
 return r.rows[0] as State|undefined??null;
}
async function leased(tx:PoolClient,id:string,token:string):Promise<boolean>{
 const q=await tx.query("SELECT claim_token,locked_until FROM api_queue.api_assessment_queue WHERE assessment_id=$1 FOR UPDATE",[id]);
 if(q.rows[0]?.claim_token!==token||new Date(q.rows[0].locked_until).getTime()<=Date.now())return false;
 const a=await tx.query("SELECT status FROM api_assessments WHERE id=$1 FOR UPDATE",[id]);
 return a.rows[0]?.status==="PROCESSING";
}
function check(s:State,tenant:string,op:Op):string|null{
 try {
  const c:PtClaims=verifyTestPermit(s.signed_token);
  if(c.permitId!==s.permit_id||digest(s.signed_token)!==s.token_hash)throw new PermitError("PERMIT_INTEGRITY_MISMATCH");
  if(s.revoked_at)throw new PermitError("PERMIT_REVOKED");
  if(new Date(s.expires_at).getTime()<=Date.now())throw new PermitError("PERMIT_EXPIRED");
  if(s.target_lifecycle!=="ACTIVE"||s.target_environment!=="SYNTHETIC")throw new PermitError("TARGET_NOT_SYNTHETIC_ACTIVE");
  enforcePermit(c,{tenantId:tenant,targetId:s.target_id,scopeId:s.scope_id,
   specificationId:s.specification_id,specificationVersion:s.specification_version,
   specFingerprint:s.spec_fingerprint,targetVerificationVersion:s.current_verification,
   targetScopeRevision:s.current_scope_revision,fixtureId:s.fixture_id,
   operationKey:op.operation_key,method:op.method,path:op.path});
  if(c.maxEvaluations!==s.max_evaluations||c.ratePerMinute!==s.rate_per_minute||
    c.maxConcurrency!==s.max_concurrency||c.deadlineMs!==s.deadline_ms)return "PERMIT_POLICY_MISMATCH";
  if(s.target_verification_version!==s.current_verification||s.target_scope_revision!==s.current_scope_revision)
   return "TARGET_SCOPE_CHANGED";
  if(new Date(s.job_deadline).getTime()<=Date.now())return "JOB_DEADLINE_EXPIRED";
  if(!fixtureOperation(op.method,op.path))return "METHOD_OR_FIXTURE_DENIED";
  return null;
 }catch(e){return e instanceof PermitError?e.code:"PERMIT_INVALID";}
}
async function stopActive(tx:PoolClient,tenant:string):Promise<boolean>{
 const r=await tx.query("SELECT enabled FROM api_pt_stop WHERE tenant_id=$1 FOR UPDATE",[tenant]);
 return r.rows[0]?.enabled!==false;
}
async function opFor(tx:PoolClient,specId:string,key:string):Promise<Op>{
 const r=await tx.query("SELECT operation_key,method,path FROM api_inventory_operations WHERE specification_id=$1 AND operation_key=$2",[specId,key]);
 return r.rows[0] as Op|undefined??empty(key);
}
async function receipt(tx:PoolClient,tenant:string,id:string,pid:string,op:Op,
 decision:"ALLOWED"|"DENIED"|"SKIPPED",outcome:string,code:string,budget:number,
 result?:{httpStatus:number;responseBytes:number;responseHash:string;durationMs:number}):Promise<void>{
 const meta=await tx.query(
  "SELECT s.specification_version,s.target_scope_revision,s.max_evaluations,p.token_hash FROM api_pt_jobs j JOIN api_pt_scopes s ON s.id=j.scope_id AND s.tenant_id=j.tenant_id JOIN api_pt_permits p ON p.id=j.permit_id AND p.tenant_id=j.tenant_id WHERE j.assessment_id=$1",[id]);
 if(!meta.rowCount)throw new Error("PT_RECEIPT_CONTEXT_NOT_FOUND");
 const seq=await tx.query("SELECT count(*)::int+1 AS next_sequence FROM api_pt_receipts WHERE assessment_id=$1",[id]);
 const m=meta.rows[0];
 await tx.query("INSERT INTO api_pt_receipts(id,tenant_id,assessment_id,permit_id,operation_key,method,path,fixture_id,specification_version,scope_revision,permit_hash,evaluation_sequence,budget_remaining,decision,outcome,code,http_status,response_bytes,response_hash,duration_ms,budget_consumed) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21) ON CONFLICT(tenant_id,assessment_id,operation_key) DO NOTHING",
 [uuid(),tenant,id,pid,op.operation_key,op.method,op.path,FIXTURE_ID,
  m.specification_version,m.target_scope_revision,m.token_hash,seq.rows[0].next_sequence,
  Math.max(0,m.max_evaluations-budget),decision,outcome,code,result?.httpStatus??null,
  result?.responseBytes??null,result?.responseHash??null,result?.durationMs??null,budget]);
}
async function audit(tx:PoolClient,tenant:string,id:string,action:string,detail:string):Promise<void>{
 await tx.query("INSERT INTO api_pt_events(id,tenant_id,subject_id,action,details) VALUES($1,$2,$3,$4,$5::jsonb)",
  [uuid(),tenant,id,action,JSON.stringify({code:detail})]);
}
async function reserve(tenant:string,id:string,token:string,opKey:string):Promise<Admission>{
 return withWorkerTenant(tenant,async tx=>{
  if(await stopActive(tx,tenant))return {decision:"LEASE_LOST",code:"EMERGENCY_STOP_ACTIVE",op:empty(opKey)};
  const s=await context(tx,tenant,id,true);
  if(!s)return {decision:"LEASE_LOST",code:"PT_JOB_GONE",op:empty(opKey)};
  if(!await leased(tx,id,token))return {decision:"LEASE_LOST",code:"LEASE_NOT_OWNED",op:empty(opKey)};
  const op=await opFor(tx,s.specification_id,opKey);
  const already=await tx.query("SELECT state FROM api_pt_ledger WHERE assessment_id=$1 AND operation_key=$2",[id,opKey]);
  if(already.rowCount){
   if(already.rows[0].state==="RESERVED"){
    // A previous process may have performed the fixture injection before crashing.
    // Count the reservation as consumed, but NEVER replay the interaction.
    await tx.query("UPDATE api_pt_ledger SET state='UNCERTAIN',settled_at=now() WHERE assessment_id=$1 AND operation_key=$2",[id,opKey]);
    await tx.query("UPDATE api_pt_permits SET reserved=reserved-1,consumed=consumed+1 WHERE id=$1",[s.permit_id]);
    await receipt(tx,tenant,id,s.permit_id,op,"SKIPPED","UNKNOWN_AFTER_WORKER_CRASH","RESERVATION_RECOVERED_NO_REPLAY",s.consumed+1);
    await audit(tx,tenant,id,"PT_UNCERTAIN_RESERVATION","RESERVATION_RECOVERED_NO_REPLAY");
   }
   return {decision:"SKIPPED",code:"OPERATION_ALREADY_ADMITTED",op};
  }
  let code=check(s,tenant,op);
  if(!code&&s.operation_keys.includes(opKey)===false)code="OPERATION_OUT_OF_SCOPE";
  if(!code&&s.consumed+s.reserved>=s.max_evaluations)code="PERMIT_BUDGET_EXHAUSTED";
  if(!code&&s.rate_used>=s.rate_per_minute&&Date.now()-new Date(s.rate_start).getTime()<60000)code="RATE_LIMIT";
  if(code){
   await receipt(tx,tenant,id,s.permit_id,op,"DENIED","NOT_EXECUTED",code,s.consumed);
   await audit(tx,tenant,id,"PT_OPERATION_DENIED",code);
   return {decision:"DENIED",code,op};
  }
  const reset=Date.now()-new Date(s.rate_start).getTime()>=60000;
  await tx.query("UPDATE api_pt_permits SET reserved=reserved+1,rate_used=CASE WHEN $2 THEN 1 ELSE rate_used+1 END,rate_start=CASE WHEN $2 THEN now() ELSE rate_start END WHERE id=$1",
   [s.permit_id,reset]);
  await tx.query("INSERT INTO api_pt_ledger(id,tenant_id,assessment_id,permit_id,operation_key,state) VALUES($1,$2,$3,$4,$5,'RESERVED')",
   [uuid(),tenant,id,s.permit_id,opKey]);
  return {decision:"RESERVED",code:"RESERVED",op};
 });
}
async function execute(tenant:string,id:string,token:string,a:Admission):Promise<boolean>{
 return withWorkerTenant(tenant,async tx=>{
  if(await stopActive(tx,tenant))return false;
  const s=await context(tx,tenant,id,true);
  if(!s||!await leased(tx,id,token))return false;
  const op=await opFor(tx,s.specification_id,a.op.operation_key);
  const ledger=await tx.query("SELECT state FROM api_pt_ledger WHERE assessment_id=$1 AND operation_key=$2 FOR UPDATE",[id,op.operation_key]);
  if(ledger.rows[0]?.state!=="RESERVED")return false;
  const code=check(s,tenant,op);
  if(code){
   await tx.query("UPDATE api_pt_ledger SET state='UNCERTAIN',settled_at=now() WHERE assessment_id=$1 AND operation_key=$2",[id,op.operation_key]);
   await tx.query("UPDATE api_pt_permits SET reserved=reserved-1,consumed=consumed+1 WHERE id=$1",[s.permit_id]);
   await receipt(tx,tenant,id,s.permit_id,op,"DENIED","NOT_EXECUTED",code,s.consumed+1);
   await audit(tx,tenant,id,"PT_ADMISSION_REVOKED",code);
   return true;
  }
  // Keep target, permit, global stop and queue row locks THROUGH the short in-process
  // interaction. Revocation/cancellation/stop serialize at the next operation boundary.
  let outcome:"FIXTURE_RESPONSE"|"FIXTURE_ERROR"="FIXTURE_ERROR";
  let metadata:{httpStatus:number;responseBytes:number;responseHash:string;durationMs:number}|undefined;
  try {
   const r=await evaluateFixture({operationKey:op.operation_key,method:op.method as "GET"|"HEAD",path:op.path as "/bills"|"/status"});
   metadata=r;outcome=r.outcome==="FIXTURE_RESPONSE"?"FIXTURE_RESPONSE":"FIXTURE_ERROR";
  }catch{outcome="FIXTURE_ERROR";}
  await tx.query("UPDATE api_pt_ledger SET state='CONSUMED',settled_at=now() WHERE assessment_id=$1 AND operation_key=$2",[id,op.operation_key]);
  await tx.query("UPDATE api_pt_permits SET reserved=reserved-1,consumed=consumed+1 WHERE id=$1",[s.permit_id]);
  await receipt(tx,tenant,id,s.permit_id,op,"ALLOWED",outcome,outcome==="FIXTURE_ERROR"?"FIXTURE_FAILURE":"FIXTURE_EVALUATED",
   s.consumed+1,metadata);
  await audit(tx,tenant,id,"PT_FIXTURE_EVALUATION",outcome);
  return true;
 });
}
async function finalize(tenant:string,id:string,token:string):Promise<void>{
 await withWorkerTenant(tenant,async tx=>{
  if(await stopActive(tx,tenant))return;
  const s=await context(tx,tenant,id,true);
  if(!s||!await leased(tx,id,token))return;
  const rows=await tx.query("SELECT operation_key,decision,outcome,code FROM api_pt_receipts WHERE assessment_id=$1 ORDER BY created_at,id",[id]);
  const ok=rows.rowCount===s.operation_keys.length&&rows.rows.every(x=>x.decision==="ALLOWED"&&x.outcome==="FIXTURE_RESPONSE");
  const counts={allowed:rows.rows.filter(x=>x.decision==="ALLOWED").length,
   denied:rows.rows.filter(x=>x.decision==="DENIED").length,
   skipped:rows.rows.filter(x=>x.decision==="SKIPPED").length};
  const report={schemaVersion:"pt-fixture-report-v1",assessmentId:id,scopeId:s.scope_id,permitId:s.permit_id,
   targetId:s.target_id,specificationId:s.specification_id,specificationVersion:s.specification_version,
   fixtureId:FIXTURE_ID,profile:"SYNTHETIC_PT_READ_ONLY",mode:"SYNTHETIC_PT_FIXTURE",status:ok?"COMPLETED":"FAILED",
   counts,budgetConsumed:s.consumed,budgetReserved:s.reserved,results:rows.rows,customerNetworkRequests:0,
   confirmedCustomerVulnerabilities:[],verifiedFixed:false,syntheticOnly:true,runtimeCustomerValidation:false,
   limitations:["Only trusted in-memory Fastify GET/HEAD fixtures evaluated","Main Platform Host permits not available",
    "No real customer API was contacted","No vulnerability-detection rules were executed",
    "NO EVIDENCE != SAFE","CI PASS != VERIFIED_FIXED"]};
  await tx.query("INSERT INTO api_pt_reports(id,tenant_id,assessment_id,projection) VALUES($1,$2,$3,$4::jsonb) ON CONFLICT(tenant_id,assessment_id) DO NOTHING",
   [uuid(),tenant,id,JSON.stringify(report)]);
  await tx.query("UPDATE api_assessments SET status=$2,error_code=$3,completed_at=now() WHERE id=$1 AND status='PROCESSING'",
   [id,ok?"COMPLETED":"FAILED",ok?null:"PT_PARTIAL_OR_DENIED"]);
  await audit(tx,tenant,id,ok?"PT_FIXTURE_JOB_COMPLETED":"PT_FIXTURE_JOB_FAILED",ok?"SYNTHETIC_ONLY":"PT_PARTIAL_OR_DENIED");
  await tx.query("DELETE FROM api_queue.api_assessment_queue WHERE assessment_id=$1 AND claim_token=$2",[id,token]);
 });
}
/** Phase06 uses the existing private assessment queue. No parallel PT scheduler. */
export async function processPtJob(tenant:string,id:string,token:string):Promise<void>{
 try{
  const operations=await withWorkerTenant(tenant,async tx=>{
   const r=await tx.query("SELECT j.operation_keys FROM api_pt_jobs j WHERE j.assessment_id=$1",[id]);
   return r.rows[0]?.operation_keys as string[]|undefined;
  });
  if(!operations)throw new Error("PT_JOB_CONFIG_NOT_FOUND");
  for(const k of operations){
   const admission=await reserve(tenant,id,token,k);
   if(admission.decision==="LEASE_LOST")return;
   if(admission.decision==="RESERVED"&&!await execute(tenant,id,token,admission))return;
  }
  await finalize(tenant,id,token);
 }catch{
  await withWorkerTenant(tenant,async tx=>{
   const q=await tx.query("SELECT claim_token FROM api_queue.api_assessment_queue WHERE assessment_id=$1 FOR UPDATE",[id]);
   if(q.rows[0]?.claim_token!==token)return;
   // Any reservation surviving a publication exception is a potential fixture
   // evaluation. Conservatively consume it, never refund or replay it.
   // Settlement and FAILED state publish in a single transaction.
   const abandoned=await tx.query(
    "SELECT l.permit_id,l.operation_key FROM api_pt_ledger l WHERE l.assessment_id=$1 AND l.state='RESERVED' FOR UPDATE",[id]);
   for(const row of abandoned.rows){
    await tx.query("UPDATE api_pt_ledger SET state='UNCERTAIN',settled_at=now() WHERE assessment_id=$1 AND operation_key=$2 AND state='RESERVED'",[id,row.operation_key]);
    await tx.query("UPDATE api_pt_permits SET reserved=reserved-1,consumed=consumed+1 WHERE id=$1 AND reserved>0",[row.permit_id]);
   }
   await tx.query("UPDATE api_assessments SET status='FAILED',error_code='PT_WORKER_FAILURE',completed_at=now() WHERE id=$1 AND status='PROCESSING'",[id]);
   await audit(tx,tenant,id,"PT_WORKER_FAILURE","PT_WORKER_FAILURE");
   if(abandoned.rowCount)await audit(tx,tenant,id,"PT_UNCERTAIN_RESERVATIONS_SETTLED",String(abandoned.rowCount));
   await tx.query("DELETE FROM api_queue.api_assessment_queue WHERE assessment_id=$1 AND claim_token=$2",[id,token]);
  });
 }
}
