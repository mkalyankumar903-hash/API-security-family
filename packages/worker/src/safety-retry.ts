/** Conservative infrastructure retries ONLY before any possibly executed fixture work. */
import {emitDiagnostic} from "../../contracts/src/operational-diagnostics-v14.js";
import type {WorkerClaim} from "../../database/src/index.js";
import {withWorkerTenant,uuid} from "../../database/src/index.js";
import {persistTerminalCoverage} from "../../pt/src/terminal-coverage.js";
import {persistOrchestrationTerminal} from "../../pt/src/orchestration-terminal.js";

export type RetryClass="TRANSIENT_PRE_EXECUTION"|"NON_RETRYABLE";
const TRANSIENT=new Set(["08000","08003","08006","40001","40P01","57P01","57014"]);
export function classifyWorkerFailure(error:unknown):RetryClass{
 if(!error||typeof error!=="object")return "NON_RETRYABLE";
 const code=(error as {code?:unknown}).code;
 return typeof code==="string"&&TRANSIENT.has(code)?"TRANSIENT_PRE_EXECUTION":"NON_RETRYABLE";
}
export type RetryDisposition="NOT_RETRYABLE"|"RETRY_SCHEDULED"|"RETRY_EXHAUSTED"|"STALE";
export async function scheduleConservativeRetry(claim:WorkerClaim,error:unknown):Promise<RetryDisposition>{
 if(classifyWorkerFailure(error)!=="TRANSIENT_PRE_EXECUTION"){emitDiagnostic({kind:"WORKER_RETRY",classification:"VALIDATION",statusCode:409,attempt:claim.claim_generation});return "NOT_RETRYABLE";}
 const code=(error as {code:string}).code;
 const result=await withWorkerTenant(claim.tenant_id,async tx=>{
  // Match canonical renewal authority lock order: stop -> job/permit/target
  // -> private queue -> assessment. A concurrent revocation, emergency stop,
  // or deadline transition must serialize before retry eligibility is decided.
  const stop=await tx.query("SELECT enabled FROM api_pt_stop WHERE tenant_id=$1 FOR UPDATE",[claim.tenant_id]);
  if(stop.rows[0]?.enabled===true)return "NOT_RETRYABLE";
  const authority=await tx.query(`SELECT j.job_deadline,p.expires_at,p.revoked_at,
   t.lifecycle,t.environment,(t.scope_revision=s.target_scope_revision AND
    t.verification_version=s.target_verification_version) AS scope_ok
   FROM api_pt_jobs j JOIN api_pt_permits p ON p.id=j.permit_id AND p.tenant_id=j.tenant_id
   JOIN api_pt_scopes s ON s.id=j.scope_id AND s.tenant_id=j.tenant_id
   JOIN api_targets t ON t.id=j.target_id AND t.tenant_id=j.tenant_id
   WHERE j.assessment_id=$1 FOR UPDATE OF j,p,t`,[claim.assessment_id]);
  if(authority.rowCount){
   const a=authority.rows[0];
   const ok=await tx.query("SELECT $1::timestamptz>clock_timestamp() AND $2::timestamptz>clock_timestamp() AS valid",[a.job_deadline,a.expires_at]);
   if(a.revoked_at||a.lifecycle!=="ACTIVE"||a.environment!=="SYNTHETIC"||!a.scope_ok||!ok.rows[0].valid)return "NOT_RETRYABLE";
  }
  const q=await tx.query("SELECT claim_token,claim_generation,locked_until>clock_timestamp() AS lease_valid,retry_count FROM api_queue.api_assessment_queue WHERE assessment_id=$1 FOR UPDATE",[claim.assessment_id]);
  if(q.rows[0]?.claim_token!==claim.claim_token||Number(q.rows[0]?.claim_generation)!==claim.claim_generation||
   q.rows[0]?.lease_valid!==true)return "STALE";
  const status=await tx.query("SELECT status FROM api_assessments WHERE id=$1 FOR UPDATE",[claim.assessment_id]);
  if(status.rows[0]?.status!=="PROCESSING")return "STALE";
  // No retry at any boundary where a synthetic fixture might have been called.
  const unsafe=await tx.query(`SELECT
   EXISTS(SELECT 1 FROM api_pt_ledger WHERE assessment_id=$1) OR
   EXISTS(SELECT 1 FROM api_pt_detection_evaluations WHERE assessment_id=$1) OR
   EXISTS(SELECT 1 FROM api_pt9_stages WHERE assessment_id=$1 AND status <> 'PENDING') AS unsafe`,[claim.assessment_id]);
  if(unsafe.rows[0]?.unsafe)return "NOT_RETRYABLE";
  const count=Number(q.rows[0].retry_count);
  if(count>=3){
   await tx.query("UPDATE api_assessments SET status='FAILED',error_code='WORKER_RETRY_EXHAUSTED',completed_at=clock_timestamp() WHERE id=$1 AND status='PROCESSING'",[claim.assessment_id]);
   await persistTerminalCoverage(tx,claim.tenant_id,claim.assessment_id);
   const orchestration=await tx.query("SELECT 1 FROM api_pt9_plans WHERE assessment_id=$1",[claim.assessment_id]);
   if(orchestration.rowCount)await persistOrchestrationTerminal(tx,claim.tenant_id,claim.assessment_id,"FAILED","WORKER_RETRY_EXHAUSTED");
   await tx.query("INSERT INTO api_worker_quarantine(assessment_id,tenant_id,reason_code,attempts) VALUES($1,$2,'WORKER_RETRY_EXHAUSTED',$3) ON CONFLICT DO NOTHING",[claim.assessment_id,claim.tenant_id,count+1]);
   await tx.query("DELETE FROM api_queue.api_assessment_queue WHERE assessment_id=$1 AND claim_token=$2 AND claim_generation=$3",[claim.assessment_id,claim.claim_token,claim.claim_generation]);
   await tx.query("UPDATE api_worker_attempts SET state='FAILED',finished_at=clock_timestamp(),failure_code='WORKER_RETRY_EXHAUSTED' WHERE id=$1 AND state='ACTIVE'",[claim.attempt_id]);
   await tx.query("INSERT INTO api_worker_events(id,tenant_id,assessment_id,attempt_id,kind,code) VALUES($1,$2,$3,$4,'RETRY_EXHAUSTED','WORKER_RETRY_EXHAUSTED')",[uuid(),claim.tenant_id,claim.assessment_id,claim.attempt_id]);
   return "RETRY_EXHAUSTED";
  }
  const delay=2**(count+1);
  const elig=await tx.query("SELECT clock_timestamp()+($1::text||' seconds')::interval AS time",[delay]);
  if(authority.rowCount){
   const ok=await tx.query("SELECT $1::timestamptz>$2::timestamptz AND $3::timestamptz>$2::timestamptz AS valid",
    [authority.rows[0].job_deadline,elig.rows[0].time,authority.rows[0].expires_at]);
   if(!ok.rows[0].valid)return "NOT_RETRYABLE";
  }
  await tx.query("UPDATE api_queue.api_assessment_queue SET claim_token=NULL,locked_until=NULL,claimed_at=NULL,last_heartbeat_at=NULL,next_eligible_at=$2,retry_count=retry_count+1,last_error_code=$3 WHERE assessment_id=$1",
   [claim.assessment_id,elig.rows[0].time,"TRANSIENT_"+code]);
  await tx.query("UPDATE api_worker_attempts SET state='FAILED',finished_at=clock_timestamp(),failure_code=$2 WHERE id=$1 AND state='ACTIVE'",
   [claim.attempt_id,"TRANSIENT_"+code]);
  await tx.query("INSERT INTO api_worker_events(id,tenant_id,assessment_id,attempt_id,kind,code) VALUES($1,$2,$3,$4,'RETRY_SCHEDULED',$5)",
   [uuid(),claim.tenant_id,claim.assessment_id,claim.attempt_id,"TRANSIENT_"+code]);
  return "RETRY_SCHEDULED";
 });
 emitDiagnostic({kind:"WORKER_RETRY",classification:result==="RETRY_EXHAUSTED"?"EXHAUSTED":result==="RETRY_SCHEDULED"?"RETRY":result==="STALE"?"STALE":"VALIDATION",statusCode:result==="RETRY_SCHEDULED"?202:409,attempt:claim.claim_generation});
 return result;
}
