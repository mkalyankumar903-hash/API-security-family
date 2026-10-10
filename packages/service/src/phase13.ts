/** Phase13 commercial test-projection, no payments, permits, network scans or Host authority issuance. */
import type {FastifyInstance,FastifyRequest} from "fastify";
import {randomUUID} from "node:crypto";
import {withTenant} from "../../database/src/index.js";
import type {PoolClient} from "pg";
import {PtError} from "./pt.js";
import {verifySyntheticEvent,fingerprint,unit,features} from "../../contracts/src/commercial-v13.js";
const fail=(code:string,status=409):never=>{throw new PtError(status,code);};
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const id=(v:unknown)=>typeof v==="string"&&UUID.test(v)?v:fail("INVALID_ID",400);
const page=(r:FastifyRequest)=>{
 const q=(r.query??{}) as Record<string,unknown>;
 if(Object.keys(q).some(k=>!["limit","offset"].includes(k)))fail("INVALID_QUERY",400);
 const n=q.limit===undefined?25:Number(q.limit),o=q.offset===undefined?0:Number(q.offset);
 if(!Number.isSafeInteger(n)||n<1||n>100||!Number.isSafeInteger(o)||o<0||o>100000)fail("INVALID_PAGINATION",400);
 return {n,o};
};
const checkKey=(v:string)=>/^[a-zA-Z0-9:_-]{8,128}$/.test(v)?v:fail("INVALID_IDEMPOTENCY_KEY",400);
const month=async(tx:PoolClient)=>(await tx.query("SELECT date_trunc('month',clock_timestamp())::date AS month")).rows[0].month as string;
const lock=async(tx:PoolClient,tenant:string,feature:string)=>{await tx.query("SELECT pg_advisory_xact_lock(hashtext($1),hashtext($2))",[tenant,feature]);};
async function latest(tx:PoolClient){
 const q=await tx.query("SELECT entitlement_id,revision,state,limit_units,expires_at,feature FROM public.api_v13_entitlement_events WHERE feature='IMMUTABLE_REPORT_OBSERVED' ORDER BY revision DESC,created_at DESC,id DESC LIMIT 1");
 return q.rows[0] as {entitlement_id:string;revision:number;state:string;limit_units:number;expires_at:string;feature:string}|undefined;
}
async function totals(tx:PoolClient,m:string){
 const used=await tx.query("SELECT coalesce(sum(units),0)::int AS n FROM public.api_v13_usage_ledger WHERE month_start=$1",[m]);
 const reserved=await tx.query("SELECT coalesce(sum(units),0)::int AS n FROM public.api_v13_reservations WHERE month_start=$1 AND state='RESERVED' AND expires_at>clock_timestamp()",[m]);
 return {consumed:Number(used.rows[0].n),reserved:Number(reserved.rows[0].n)};
}
export async function projection(tenantId:string){
 return withTenant(tenantId,async tx=>{
  const e=await latest(tx),m=await month(tx),t=await totals(tx,m);
  const active=!!e&&e.state==="ISSUED"&&Date.parse(String(e.expires_at))>Date.now();
  const quota=active?e.limit_units:0;
  return {schemaVersion:"api-family-commercial-v13",tenantContext:"ISOLATED_SYNTHETIC_ONLY",
   hostAuthority:"HOST_AUTHORITY_NOT_CONFIGURED",feature:"IMMUTABLE_REPORT_OBSERVED",meterUnit:"one distinct existing immutable Phase11 report",
   billable:false,monthStart:m,entitlement:e?{id:e.entitlement_id,revision:e.revision,state:e.state,
    expiresAt:e.expires_at,syntheticOnly:true}:null,
   quota:quota,consumed:t.consumed,reserved:t.reserved,remaining:Math.max(0,quota-t.consumed-t.reserved),
   decision:active?"SYNTHETIC_PROJECTION_ONLY":"HOST_AUTHORITY_NOT_CONFIGURED"};
 });
}
/** CI-only imported signed envelope; NOT a REST endpoint or Host production verifier. */
export async function ingestSyntheticEntitlement(raw:Uint8Array,signature:string,key:Uint8Array){
 const e=verifySyntheticEvent(raw,signature,key),digest=fingerprint(raw);
 return withTenant(e.tenantId,async tx=>{
  await lock(tx,e.tenantId,e.feature);
  const duplicate=await tx.query("SELECT payload_fingerprint FROM public.api_v13_event_inbox WHERE event_id=$1",[e.eventId]);
  if(duplicate.rowCount){
   if(duplicate.rows[0].payload_fingerprint!==digest)fail("EVENT_ID_REUSE_CONFLICT");
   return {eventId:e.eventId,replay:true};
  }
  const existing=await latest(tx);
  if(existing&&(existing.entitlement_id!==e.entitlementId||e.revision!==Number(existing.revision)+1))
   fail("ENTITLEMENT_REVISION_CONFLICT");
  if(!existing&&e.revision!==1)fail("ENTITLEMENT_REVISION_CONFLICT");
  await tx.query("INSERT INTO public.api_v13_event_inbox(id,tenant_id,event_id,payload_fingerprint,revision) VALUES($1,$2,$3,$4,$5)",
   [randomUUID(),e.tenantId,e.eventId,digest,e.revision]);
  await tx.query("INSERT INTO public.api_v13_entitlement_events(id,tenant_id,entitlement_id,event_id,revision,feature,limit_units,state,issuer,audience,expires_at,payload_fingerprint) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
   [randomUUID(),e.tenantId,e.entitlementId,e.eventId,e.revision,e.feature,e.limit,e.status,e.issuer,e.audience,e.expiresAt,digest]);
  return {eventId:e.eventId,replay:false};
 });
}
export async function reserveObservedReport(t:string,reportId:string,key:string){
 id(t);id(reportId);checkKey(key);
 return withTenant(t,async tx=>{
  await lock(tx,t,"IMMUTABLE_REPORT_OBSERVED");
  const old=await tx.query("SELECT * FROM public.api_v13_reservations WHERE idempotency_key=$1",[key]);
  if(old.rowCount){
   if(old.rows[0].source_report_id!==reportId)fail("IDEMPOTENCY_CONFLICT");
   return {id:old.rows[0].id,state:old.rows[0].state,replay:true};
  }
  const e=await latest(tx);
  if(!e||e.state!=="ISSUED"||Date.parse(String(e.expires_at))<=Date.now())fail("ENTITLEMENT_UNAVAILABLE",403);
  const report=await tx.query("SELECT fingerprint FROM public.api_vapt11_reports WHERE parent_assessment_id=$1",[reportId]);
  if(!report.rowCount)fail("IMMUTABLE_REPORT_NOT_FOUND",404);
  const exists=await tx.query("SELECT id FROM public.api_v13_reservations WHERE source_report_id=$1",[reportId]);
  if(exists.rowCount)fail("SOURCE_ALREADY_ACCOUNTED");
  const m=await month(tx),usage=await totals(tx,m);
  if(usage.consumed+usage.reserved+1>e.limit_units)fail("QUOTA_EXCEEDED",429);
  const reservationId=randomUUID();
  await tx.query("INSERT INTO public.api_v13_reservations(id,tenant_id,entitlement_id,feature,source_report_id,month_start,idempotency_key,units,expires_at) VALUES($1,$2,$3,'IMMUTABLE_REPORT_OBSERVED',$4,$5,$6,1,clock_timestamp()+interval '5 minutes')",
   [reservationId,t,e.entitlement_id,reportId,m,key]);
  return {id:reservationId,state:"RESERVED",replay:false};
 });
}
export async function settleObservedReport(t:string,reservationId:string){
 id(t);id(reservationId);
 return withTenant(t,async tx=>{
  await lock(tx,t,"IMMUTABLE_REPORT_OBSERVED");
  const q=await tx.query("SELECT * FROM public.api_v13_reservations WHERE id=$1 FOR UPDATE",[reservationId]);
  if(!q.rowCount)fail("RESERVATION_NOT_FOUND",404);
  const r=q.rows[0];
  if(r.state==="SETTLED")return {id:r.id,state:"SETTLED",replay:true};
  if(r.state!=="RESERVED")fail("RESERVATION_ALREADY_CLOSED");
  if(Date.parse(String(r.expires_at))<=Date.now())fail("RESERVATION_EXPIRED");
  const report=await tx.query("SELECT fingerprint FROM public.api_vapt11_reports WHERE parent_assessment_id=$1",[r.source_report_id]);
  if(!report.rowCount)fail("IMMUTABLE_REPORT_NOT_FOUND",404);
  const current=await latest(tx);
  if(!current||current.state!=="ISSUED"||Date.parse(String(current.expires_at))<=Date.now())
   fail("ENTITLEMENT_UNAVAILABLE",403);
  const ledgerId=randomUUID();
  await tx.query("UPDATE public.api_v13_reservations SET state='SETTLED',settled_at=clock_timestamp() WHERE id=$1",[r.id]);
  await tx.query("INSERT INTO public.api_v13_usage_ledger(id,tenant_id,reservation_id,feature,source_report_id,month_start,units,source_fingerprint) VALUES($1,$2,$3,'IMMUTABLE_REPORT_OBSERVED',$4,$5,$6,$7)",
   [ledgerId,t,r.id,r.source_report_id,r.month_start,r.units,report.rows[0].fingerprint]);
  await tx.query("INSERT INTO public.api_v13_outbox(id,tenant_id,source_usage_id,payload) VALUES($1,$2,$3,$4::jsonb)",
   [randomUUID(),t,ledgerId,JSON.stringify({schemaVersion:"api-family-commercial-v13",event:"USAGE_OBSERVED",units:r.units,sourceReportId:r.source_report_id,syntheticOnly:true,delivery:"DISABLED"})]);
  return {id:r.id,state:"SETTLED",replay:false};
 });
}
export async function closeReservation(t:string,reservationId:string){
 id(t);id(reservationId);
 return withTenant(t,async tx=>{
  await lock(tx,t,"IMMUTABLE_REPORT_OBSERVED");
  const q=await tx.query("SELECT state,expires_at FROM public.api_v13_reservations WHERE id=$1 FOR UPDATE",[reservationId]);
  if(!q.rowCount)fail("RESERVATION_NOT_FOUND",404);
  if(q.rows[0].state!=="RESERVED")return {state:q.rows[0].state};
  const state=Date.parse(String(q.rows[0].expires_at))<=Date.now()?"EXPIRED":"RELEASED";
  await tx.query("UPDATE public.api_v13_reservations SET state=$2 WHERE id=$1",[reservationId,state]);
  return {state};
 });
}
/** No external snapshot -> PENDING, not a fabricated MATCHED invoice. */
export async function reconcilePending(t:string){
 id(t);
 return withTenant(t,async tx=>{
  await lock(tx,t,"IMMUTABLE_REPORT_OBSERVED");
  const m=await month(tx),tot=await totals(tx,m);
  const prior=await tx.query("SELECT id,state FROM public.api_v13_reconciliation WHERE feature='IMMUTABLE_REPORT_OBSERVED' AND month_start=$1 AND external_revision IS NULL ORDER BY created_at DESC,id DESC LIMIT 1",[m]);
  if(prior.rowCount)return prior.rows[0];
  const rid=randomUUID();
  await tx.query("INSERT INTO public.api_v13_reconciliation(id,tenant_id,feature,month_start,local_units,state) VALUES($1,$2,'IMMUTABLE_REPORT_OBSERVED',$3,$4,'PENDING_EXTERNAL_AUTHORITY')",
   [rid,t,m,tot.consumed]);
  return {id:rid,state:"PENDING_EXTERNAL_AUTHORITY"};
 });
}
export function registerPhase13Routes(app:FastifyInstance,identity:(req:FastifyRequest)=>string){
 app.get("/v13/capabilities",async()=>({schemaVersion:"api-family-commercial-v13",syntheticOnly:true,
  productionHostIntegration:false,hostAuthority:"HOST_AUTHORITY_NOT_CONFIGURED",meterDefinitions:[
   {feature:features[0],version:1,unit:"distinct existing immutable Phase11 report",billable:false}],
  scanningAuthority:false,verifiedFixedAuthority:false}));
 app.get("/v13/entitlements",async req=>({projection:await projection(identity(req))}));
 app.get("/v13/usage/summary",async req=>projection(identity(req)));
 app.get("/v13/usage/events",async req=>{
  const t=identity(req),p=page(req);
  return withTenant(t,async tx=>(await tx.query("SELECT id,feature,source_report_id AS \"sourceReportId\",units,source_fingerprint AS \"sourceFingerprint\",created_at AS \"createdAt\" FROM public.api_v13_usage_ledger ORDER BY created_at DESC,id DESC LIMIT $1 OFFSET $2",[p.n,p.o])).rows);
 });
 app.get("/v13/reservations",async req=>{
  const t=identity(req),p=page(req);
  return withTenant(t,async tx=>(await tx.query("SELECT id,feature,source_report_id AS \"sourceReportId\",units,state,expires_at AS \"expiresAt\" FROM public.api_v13_reservations ORDER BY created_at DESC,id DESC LIMIT $1 OFFSET $2",[p.n,p.o])).rows);
 });
 app.get("/v13/reconciliations",async req=>{
  const t=identity(req),p=page(req);
  return withTenant(t,async tx=>(await tx.query("SELECT id,feature,month_start AS \"monthStart\",state,local_units AS \"localUnits\",external_units AS \"externalUnits\",created_at AS \"createdAt\" FROM public.api_v13_reconciliation ORDER BY created_at DESC,id DESC LIMIT $1 OFFSET $2",[p.n,p.o])).rows);
 });
 app.get("/v13/decisions",async req=>{
  const q=(req.query??{}) as Record<string,unknown>;
  if(Object.keys(q).some(k=>!["quantity"].includes(k)))fail("INVALID_QUERY",400);
  let n:number;
  try{n=unit(q.quantity===undefined?1:Number(q.quantity));}catch{fail("INVALID_QUANTITY",400);}
  const summary=await projection(identity(req));
  return {allowed:false,code:"HOST_AUTHORITY_NOT_CONFIGURED",syntheticProjectionWouldAllow:
   summary.entitlement?.state==="ISSUED"&&n>0&&summary.remaining>=n,quantity:n,
   warning:"Commercial projection cannot grant production operation or PT authority"};
 });
}
