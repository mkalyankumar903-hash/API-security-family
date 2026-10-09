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
   const [queue,attempts,events,quarantine]=await Promise.all([
    tx.query("SELECT public.api_worker_safe_queue_status($1) AS state",[id]),
    tx.query("SELECT id,claim_generation,state,started_at,last_heartbeat_at,finished_at,failure_code FROM api_worker_attempts WHERE assessment_id=$1 ORDER BY claim_generation DESC LIMIT $2",[id,limit]),
    tx.query("SELECT kind,code,occurred_at FROM api_worker_events WHERE assessment_id=$1 ORDER BY occurred_at DESC,id DESC LIMIT $2",[id,limit]),
    tx.query("SELECT reason_code,attempts,quarantined_at FROM api_worker_quarantine WHERE assessment_id=$1",[id])
   ]);
   return {schemaVersion:"pt-worker-safety-v1",syntheticOnly:true,
    customerNetworkRequests:0,realCustomerApiTestingAuthorized:false,
    warning:"WORKER RECOVERY DOES NOT GRANT NEW SECURITY AUTHORITY",
    assessment:a.rows[0],queue:queue.rows[0]?.state??null,
    attempts:attempts.rows.map(row=>({...row,claim_generation:Number(row.claim_generation)})),events:events.rows,quarantine:quarantine.rows[0]??null};
  });
 });
}
