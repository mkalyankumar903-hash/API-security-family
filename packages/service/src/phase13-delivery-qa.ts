/** Phase13 isolated synthetic delivery qualification only. NO network transport. */
import {randomUUID} from "node:crypto";
import {emitDiagnostic} from "../../contracts/src/operational-diagnostics-v14.js";
import {withQaTenant} from "../../database/src/index.js";
import {fingerprint} from "../../contracts/src/commercial-v13.js";
const qa=()=>{if(process.env.NODE_ENV!=="test"||process.env.SYNTHETIC_AUTH_ENABLED!=="true")
 throw new Error("HOST_AUTHORITY_NOT_CONFIGURED");};
const MAX=4;
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const safe=(v:string)=>{if(!UUID.test(v))throw Error("INVALID_ID");return v;};
const event=async(tx:import("pg").PoolClient,t:string,d:string,code:string,attempt:number,diag:string|null=null)=>
 tx.query("INSERT INTO public.api_v13_qa_delivery_events(id,tenant_id,delivery_id,code,attempt_count,diagnostic) VALUES($1,$2,$3,$4,$5,$6)",
 [randomUUID(),t,d,code,attempt,diag]);
/** CI-only opt-in: the actual immutable outbox is never moved from DISABLED. */
export async function enqueueQaDelivery(tenant:string,outboxId:string){
 qa();safe(tenant);safe(outboxId);
 return withQaTenant(tenant,async tx=>{
  const source=await tx.query("SELECT id FROM public.api_v13_outbox WHERE id=$1 AND payload->>'syntheticOnly'='true' AND delivery_state='DISABLED' AND attempt_count=0",[outboxId]);
  if(!source.rowCount)throw Error("QA_SOURCE_NOT_ELIGIBLE");
  const id=randomUUID();
  const inserted=await tx.query("INSERT INTO public.api_v13_qa_delivery(id,tenant_id,outbox_id) VALUES($1,$2,$3) ON CONFLICT(tenant_id,outbox_id) DO NOTHING RETURNING id",[id,tenant,outboxId]);
  if(inserted.rowCount)await event(tx,tenant,id,"ENQUEUED",0);
  const actual=inserted.rowCount?id:(await tx.query("SELECT id FROM public.api_v13_qa_delivery WHERE outbox_id=$1",[outboxId])).rows[0].id as string;
  return {id:actual,replay:!inserted.rowCount};
 });
}
/** A locked, fenced claim is never a production webhook permission. */
export async function claimQaDelivery(tenant:string,deliveryId:string,leaseSeconds=2){
 qa();safe(tenant);safe(deliveryId);
 if(!Number.isSafeInteger(leaseSeconds)||leaseSeconds<1||leaseSeconds>30)throw Error("INVALID_QA_LEASE");
 return withQaTenant(tenant,async tx=>{
  const q=await tx.query("SELECT * FROM public.api_v13_qa_delivery WHERE id=$1 FOR UPDATE",[deliveryId]);
  if(!q.rowCount)throw Error("QA_DELIVERY_NOT_FOUND");
  const d=q.rows[0];const n=Number(d.attempt_count);
  if(d.state==="ACKED"||d.state==="DEAD_LETTER")return {state:d.state,replay:true};
  if(d.state==="LEASED"&&Date.parse(String(d.lease_until))>Date.now())throw Error("QA_LEASE_IN_USE");
  if(d.state==="RETRY"&&Date.parse(String(d.next_attempt_at))>Date.now())throw Error("QA_BACKOFF_ACTIVE");
  if(n>=MAX){
   await tx.query("UPDATE public.api_v13_qa_delivery SET state='DEAD_LETTER',lease_token=NULL,lease_until=NULL,diagnostic='MAX_ATTEMPTS' WHERE id=$1",[deliveryId]);
   await event(tx,tenant,deliveryId,"DEAD_LETTER",n,"MAX_ATTEMPTS");
   return {state:"DEAD_LETTER",replay:false};
  }
  const token=randomUUID();
  await tx.query("UPDATE public.api_v13_qa_delivery SET state='LEASED',attempt_count=attempt_count+1,lease_token=$2,lease_until=clock_timestamp()+$3::int*interval '1 second',diagnostic=NULL WHERE id=$1",
   [deliveryId,token,leaseSeconds]);
  await event(tx,tenant,deliveryId,"CLAIMED",n+1);
  return {state:"LEASED",token,attempt:n+1,replay:false};
 });
}
/** Synthetic sink persists only a redacted deterministic receipt, no HTTP or callback. */
export async function consumeQaSink(tenant:string,deliveryId:string,token:string){
 qa();safe(tenant);safe(deliveryId);safe(token);
 return withQaTenant(tenant,async tx=>{
  const d=await tx.query("SELECT state,lease_token,lease_until,outbox_id FROM public.api_v13_qa_delivery WHERE id=$1 FOR UPDATE",[deliveryId]);
  if(!d.rowCount||d.rows[0].state!=="LEASED"||d.rows[0].lease_token!==token||Date.parse(String(d.rows[0].lease_until))<=Date.now())throw Error("QA_STALE_LEASE");
  const o=await tx.query("SELECT source_usage_id,payload FROM public.api_v13_outbox WHERE id=$1 AND delivery_state='DISABLED'",[d.rows[0].outbox_id]);
  if(!o.rowCount||o.rows[0].payload.syntheticOnly!==true)throw Error("QA_SOURCE_NOT_ELIGIBLE");
  const digest=fingerprint(JSON.stringify({id:o.rows[0].source_usage_id,event:"USAGE_OBSERVED",version:1}));
  const saved=await tx.query("INSERT INTO public.api_v13_qa_sink_receipts(id,tenant_id,delivery_id,redacted_payload_hash) VALUES($1,$2,$3,$4) ON CONFLICT(tenant_id,delivery_id) DO NOTHING RETURNING id",
   [randomUUID(),tenant,deliveryId,digest]);
  return {replay:!saved.rowCount,receiptHash:digest};
 });
}
export async function ackQaDelivery(tenant:string,deliveryId:string,token:string){
 qa();safe(tenant);safe(deliveryId);safe(token);
 return withQaTenant(tenant,async tx=>{
  const q=await tx.query("SELECT state,lease_token,lease_until,attempt_count FROM public.api_v13_qa_delivery WHERE id=$1 FOR UPDATE",[deliveryId]);
  if(!q.rowCount)throw Error("QA_DELIVERY_NOT_FOUND");
  const d=q.rows[0];
  if(d.state==="ACKED")return {state:"ACKED",replay:true};
  if(d.state!=="LEASED"||d.lease_token!==token||Date.parse(String(d.lease_until))<=Date.now())throw Error("QA_STALE_LEASE");
  const receipt=await tx.query("SELECT id FROM public.api_v13_qa_sink_receipts WHERE delivery_id=$1",[deliveryId]);
  if(!receipt.rowCount)throw Error("QA_SINK_ACK_REQUIRED");
  await tx.query("UPDATE public.api_v13_qa_delivery SET state='ACKED',lease_token=NULL,lease_until=NULL,acked_at=clock_timestamp() WHERE id=$1",[deliveryId]);
  await event(tx,tenant,deliveryId,"ACKED",Number(d.attempt_count));
  return {state:"ACKED",replay:false};
 });
}
/** No unsafe exception strings, URLs, tokens or payloads in durable diagnostics. */
export async function failQaDelivery(tenant:string,deliveryId:string,token:string){
 qa();safe(tenant);safe(deliveryId);safe(token);
 const result=await withQaTenant(tenant,async tx=>{
  const q=await tx.query("SELECT state,lease_token,lease_until,attempt_count FROM public.api_v13_qa_delivery WHERE id=$1 FOR UPDATE",[deliveryId]);
  if(!q.rowCount||q.rows[0].state!=="LEASED"||q.rows[0].lease_token!==token||
   Date.parse(String(q.rows[0].lease_until))<=Date.now())throw Error("QA_STALE_LEASE");
  const n=Number(q.rows[0].attempt_count),terminal=n>=MAX,seconds=Math.min(8,2**(n-1));
  await tx.query("UPDATE public.api_v13_qa_delivery SET state=$2,lease_token=NULL,lease_until=NULL,diagnostic=$3,next_attempt_at=clock_timestamp()+$4::int*interval '1 second' WHERE id=$1",
   [deliveryId,terminal?"DEAD_LETTER":"RETRY",terminal?"MAX_ATTEMPTS":"SYNTHETIC_RETRY",terminal?0:seconds]);
  await event(tx,tenant,deliveryId,terminal?"DEAD_LETTER":"RETRY_SCHEDULED",n,terminal?"MAX_ATTEMPTS":"SYNTHETIC_RETRY");
  return {state:terminal?"DEAD_LETTER":"RETRY",backoffSeconds:terminal?0:seconds};
 });
 emitDiagnostic({kind:"QA_DELIVERY",classification:result.state==="DEAD_LETTER"?"EXHAUSTED":"RETRY",statusCode:result.state==="DEAD_LETTER"?409:202});
 return result;
}
