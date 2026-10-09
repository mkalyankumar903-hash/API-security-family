/** Phase09 append-only terminal diagnostics; not a successful PT report. */
import type {PoolClient} from "pg";
import {uuid} from "../../database/src/index.js";
import {planFingerprint} from "./detection.js";
export async function persistOrchestrationTerminal(tx:PoolClient,tenant:string,id:string,
 status:"FAILED"|"CANCELLED",code:string):Promise<void>{
 const snapshot=await tx.query("SELECT p.fingerprint,p.plan FROM api_pt9_plans p WHERE p.assessment_id=$1",[id]);
 if(!snapshot.rowCount)return;
 const stages=await tx.query("SELECT stage_id,status,planned,reason FROM api_pt9_stages WHERE assessment_id=$1 ORDER BY ordinal",[id]);
 const evaluations=await tx.query("SELECT state,count(*)::int AS count FROM api_pt_detection_evaluations WHERE assessment_id=$1 GROUP BY state",[id]);
 const counts=Object.fromEntries(evaluations.rows.map(r=>[r.state,r.count])) as Record<string,number>;
 const planned=(snapshot.rows[0].plan as {maxEvaluations:number}).maxEvaluations;
 const projection={schemaVersion:"pt-orchestration-terminal-v1",orchestrationId:id,status,code,
  planFingerprint:snapshot.rows[0].fingerprint,stages:stages.rows,
  accounting:{planned,consumed:counts.CONSUMED??0,uncertain:counts.UNCERTAIN??0,
   reserved:counts.RESERVED??0,notRun:Math.max(0,planned-(counts.CONSUMED??0)-(counts.UNCERTAIN??0)-(counts.RESERVED??0))},
  assessmentComplete:false,syntheticOnly:true,customerRuntimeVerified:false,verifiedFixed:false,
  customerNetworkRequests:0,notice:"Partial or failed synthetic execution is not a successful security report."};
 await tx.query("INSERT INTO api_pt9_terminal(id,tenant_id,assessment_id,status,code,projection,fingerprint) VALUES($1,$2,$3,$4,$5,$6::jsonb,$7) ON CONFLICT(tenant_id,assessment_id) DO NOTHING",
  [uuid(),tenant,id,status,code,JSON.stringify(projection),planFingerprint(projection)]);
}
