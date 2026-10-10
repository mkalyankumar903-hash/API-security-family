/** Phase10 read-only execution safety diagnostics: tenant-aware and synthetic-only. */
import type {FastifyInstance,FastifyRequest} from "fastify";
import {withTenant} from "../../database/src/index.js";

const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
export function registerWorkerSafetyRoutes(app:FastifyInstance,identity:(req:FastifyRequest)=>string):void{
 app.get("/v10/workers/assessments/:id/execution",async(req,reply)=>{
  const id=(req.params as {id?:string}).id;
  if(!id||!UUID.test(id))return reply.code(400).send({error:"INVALID_ASSESSMENT_ID"});
  const params=(req.query??{}) as Record<string,unknown>;
  const limit=params.limit===undefined?20:Number(params.limit);
  if(Object.keys(params).some(k=>k!=="limit")||!Number.isInteger(limit)||limit<1||limit>25)
   return reply.code(400).send({error:"INVALID_HISTORY_LIMIT"});
  return withTenant(identity(req),async tx=>{
   const a=await tx.query("SELECT id,status,engine_version,error_code,created_at,completed_at FROM api_assessments WHERE id=$1",[id]);
   if(!a.rowCount)return reply.code(404).send({error:"ASSESSMENT_NOT_FOUND"});
   const [queue,attempts,events,quarantine,governor,checkpoints,evaluations]=await Promise.all([
    tx.query("SELECT public.api_worker_safe_queue_status($1) AS state",[id]),
    tx.query("SELECT id,claim_generation,state,started_at,last_heartbeat_at,finished_at,failure_code FROM api_worker_attempts WHERE assessment_id=$1 ORDER BY claim_generation DESC LIMIT $2",[id,limit]),
    tx.query("SELECT kind,code,occurred_at FROM api_worker_events WHERE assessment_id=$1 ORDER BY occurred_at DESC,id DESC LIMIT $2",[id,limit]),
    tx.query("SELECT reason_code,attempts,quarantined_at FROM api_worker_quarantine WHERE assessment_id=$1",[id]),
    tx.query(`SELECT j.job_deadline,p.id AS permit_id,p.expires_at AS permit_expires_at,
      p.revoked_at AS permit_revoked_at,p.consumed,p.reserved,p.rate_used,
      t.lifecycle AS target_lifecycle,
      COALESCE(st.enabled,false) AS emergency_stopped
     FROM api_pt_jobs j JOIN api_pt_permits p ON p.id=j.permit_id AND p.tenant_id=j.tenant_id
     JOIN api_targets t ON t.id=j.target_id AND t.tenant_id=j.tenant_id
     LEFT JOIN api_pt_stop st ON st.tenant_id=j.tenant_id
     WHERE j.assessment_id=$1`,[id]),
    tx.query("SELECT stage_id,status,ordinal,reason FROM api_pt9_stages WHERE assessment_id=$1 ORDER BY ordinal LIMIT 6",[id]),
    tx.query(`SELECT state,count(*)::int AS total FROM (
      SELECT state FROM api_pt_detection_evaluations WHERE assessment_id=$1
      UNION ALL SELECT state FROM api_pt_ledger WHERE assessment_id=$1
    ) receipt GROUP BY state ORDER BY state`,[id])
   ]);
   return {schemaVersion:"pt-worker-safety-v1",syntheticOnly:true,
    customerNetworkRequests:0,realCustomerApiTestingAuthorized:false,
    warning:"WORKER RECOVERY DOES NOT GRANT NEW SECURITY AUTHORITY",
    assessment:a.rows[0],queue:queue.rows[0]?.state??null,
    execution:{
      queueRecordId:queue.rows[0]?.state?id:null,
      currentAttemptId:queue.rows[0]?.state?.queueState==="LEASED"?
       (attempts.rows.find(x=>x.state==="ACTIVE")?.id??null):null,
      lifecycle:a.rows[0].status,
      deadline:governor.rows[0]?.job_deadline??null,
      authorization:governor.rowCount?{
       permitId:governor.rows[0].permit_id,
       permitExpiresAt:governor.rows[0].permit_expires_at,
       status:governor.rows[0].permit_revoked_at?"REVOKED":
        governor.rows[0].emergency_stopped?"EMERGENCY_STOPPED":
        governor.rows[0].target_lifecycle!=="ACTIVE"?"TARGET_NOT_ACTIVE":"VALIDITY_REQUIRES_GOVERNOR_RECHECK",
       consumed:governor.rows[0].consumed,reserved:governor.rows[0].reserved,
       rateUsed:governor.rows[0].rate_used
      }:null,
      checkpoints:checkpoints.rows,receipts:evaluations.rows,
      terminalReason:a.rows[0].error_code??null,
      provenance:"POSTGRESQL_PRIVATE_WORKER_AND_GOVERNED_LEDGER"
    },
    attempts:attempts.rows.map(row=>({...row,claim_generation:Number(row.claim_generation)})),events:events.rows,quarantine:quarantine.rows[0]??null};
  });
 });
}
