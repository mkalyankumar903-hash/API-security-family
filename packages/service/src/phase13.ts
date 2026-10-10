/** Phase13 commercial test-projection, no payments, permits, network scans or Host authority issuance. */
import type {FastifyInstance,FastifyRequest} from "fastify";
import {randomUUID} from "node:crypto";
import {withTenant,phase13TestFaultBarrier} from "../../database/src/index.js";
import type {PoolClient} from "pg";
import {PtError} from "./pt.js";
import {verifyStoredTestPermit,type PtClaims} from "../../pt/src/permit.js";
import {verifySyntheticEvent,verifySyntheticExternalSnapshot,verifySyntheticCorrection,fingerprint,unit,features,commercialFeatureCatalog,type Feature} from "../../contracts/src/commercial-v13.js";
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
const month=async(tx:PoolClient)=>(await tx.query("SELECT date_trunc('month',clock_timestamp() AT TIME ZONE 'UTC')::date AS month")).rows[0].month as string;
const lock=async(tx:PoolClient,tenant:string,feature:string)=>{await tx.query("SELECT pg_advisory_xact_lock(hashtext($1),hashtext($2))",[tenant,feature]);};
async function latest(tx:PoolClient,feature:Feature=features[0]){
 const q=await tx.query("SELECT entitlement_id,revision,state,limit_units,expires_at,feature FROM public.api_v13_entitlement_events WHERE feature=$1 ORDER BY revision DESC,created_at DESC,id DESC LIMIT 1",[feature]);
 return q.rows[0] as {entitlement_id:string;revision:number;state:string;limit_units:number;expires_at:string;feature:string}|undefined;
}
async function totals(tx:PoolClient,m:string,feature:Feature=features[0]){
 const used=await tx.query("SELECT coalesce(sum(units),0)::int AS n FROM public.api_v13_usage_ledger WHERE month_start=$1 AND feature=$2",[m,feature]);
 const adjustments=await tx.query("SELECT coalesce(sum(unit_delta),0)::int AS n FROM public.api_v13_usage_corrections WHERE source_usage_id IN (SELECT id FROM public.api_v13_usage_ledger WHERE month_start=$1 AND feature=$2)",[m,feature]);
 const reserved=await tx.query("SELECT coalesce(sum(units),0)::int AS n FROM public.api_v13_reservations WHERE month_start=$1 AND feature=$2 AND state='RESERVED' AND expires_at>clock_timestamp()",[m,feature]);
 return {consumed:Number(used.rows[0].n)+Number(adjustments.rows[0].n),reserved:Number(reserved.rows[0].n)};
}
export async function projection(tenantId:string,feature:Feature=features[0]){
 return withTenant(tenantId,async tx=>{
  const e=await latest(tx,feature),m=await month(tx),t=await totals(tx,m,feature);
  const active=!!e&&e.state==="ISSUED"&&Date.parse(String(e.expires_at))>Date.now();
  const quota=active?e.limit_units:0;
  return {schemaVersion:"api-family-commercial-v13",tenantContext:"ISOLATED_SYNTHETIC_ONLY",
   hostAuthority:"HOST_AUTHORITY_NOT_CONFIGURED",feature,meterUnit:feature==="IMMUTABLE_REPORT_OBSERVED"?"one distinct immutable Phase11 report":feature==="OFFLINE_API_ASSESSMENT_COMPLETED"?"one successful immutable offline child report":"one signed synthetic governed PT outcome",
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
  const existing=await latest(tx,e.feature);
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
/** Resolve only authoritative terminal sources. Existing immutable parent report is a minimum
 * prerequisite for every meter; offline/PT also require their own successful child evidence.
 * This never initiates an assessment and never authorizes a network. */
async function qualifiedSource(tx:PoolClient,reportId:string,feature:Feature){
 const q=await tx.query(`SELECT r.fingerprint AS report_fingerprint,
   v.offline_assessment_id,v.pt_assessment_id,v.mode,
   a.status AS parent_status,o.status AS offline_status,
   off.projection AS offline_projection,
   pt.status AS pt_status,pr.fingerprint AS pt_fingerprint,pr.projection AS pt_projection,
   permit.token_hash AS permit_hash,permit.signed_body AS stored_permit_body,
   permit.claims AS stored_permit_claims,permit.revoked_at AS permit_revoked,
   permit.scope_id AS stored_permit_scope_id,permit.expires_at AS stored_permit_expires_at,
   pr.created_at AS pt_report_created_at
   FROM public.api_vapt11_reports r
   JOIN public.api_vapt11_assessments v ON v.tenant_id=r.tenant_id AND v.parent_assessment_id=r.parent_assessment_id
   JOIN public.api_assessments a ON a.tenant_id=v.tenant_id AND a.id=v.parent_assessment_id
   JOIN public.api_assessments o ON o.tenant_id=v.tenant_id AND o.id=v.offline_assessment_id
   LEFT JOIN public.api_reports off ON off.tenant_id=o.tenant_id AND off.assessment_id=o.id
   LEFT JOIN public.api_assessments pt ON pt.tenant_id=v.tenant_id AND pt.id=v.pt_assessment_id
   LEFT JOIN public.api_pt9_reports pr ON pr.tenant_id=pt.tenant_id AND pr.assessment_id=pt.id
   LEFT JOIN public.api_pt_jobs j ON j.tenant_id=pt.tenant_id AND j.assessment_id=pt.id
   LEFT JOIN public.api_pt_permits permit ON permit.tenant_id=j.tenant_id AND permit.id=j.permit_id
   WHERE r.parent_assessment_id=$1`,[reportId]);
 if(!q.rowCount)fail("IMMUTABLE_REPORT_NOT_FOUND",404);
 const v=q.rows[0];
 if(v.parent_status!=="COMPLETED")fail("SOURCE_NOT_SUCCESSFUL");
 if(feature==="IMMUTABLE_REPORT_OBSERVED")
  return {fingerprint:String(v.report_fingerprint),child:reportId,type:"IMMUTABLE_PARENT_REPORT",permit:null};
 if(v.offline_status!=="COMPLETED"||v.offline_projection?.mode!=="SPEC_ONLY")fail("OFFLINE_TERMINAL_EVIDENCE_MISSING");
 if(feature==="OFFLINE_API_ASSESSMENT_COMPLETED")
  return {fingerprint:fingerprint(JSON.stringify({report:v.report_fingerprint,offlineId:v.offline_assessment_id,projection:v.offline_projection})),
    child:String(v.offline_assessment_id),type:"PERSISTED_OFFLINE_REPORT",permit:null};
 if(v.mode!=="GOVERNED_SYNTHETIC"||v.pt_status!=="COMPLETED"||
   v.pt_projection?.status!=="COMPLETED"||v.pt_projection?.syntheticOnly!==true||
   v.pt_projection?.verifiedFixed!==false||v.pt_projection?.customerRuntimeVerified!==false||
   typeof v.permit_hash!=="string"||!/^[a-f0-9]{64}$/.test(v.permit_hash)||
   typeof v.stored_permit_body!=="string"||v.stored_permit_body.length<32||
   !v.stored_permit_claims||v.permit_revoked)
  fail("SIGNED_GOVERNED_PT_EVIDENCE_MISSING");
 // Reconstruct and independently validate the original signed CI permit without
 // persisting a bearer. Authenticate at the SIGNED permit's own validity interval:
 // this observation must not require a historic completed permit to remain live.
 // Successful PT terminal and consumed receipt evidence are checked independently.
 try{
  const claimed=v.stored_permit_claims as PtClaims;
  const proofInstant=claimed.notBefore+1;
  const signed=verifyStoredTestPermit(claimed,String(v.permit_hash),
    String(v.stored_permit_body),proofInstant);
  const lineage=await tx.query("SELECT "+
   "(SELECT count(*)::int FROM public.api_pt9_stages st WHERE st.assessment_id=$1 AND st.status<>'COMPLETED') AS unfinished,"+
   "(SELECT count(*)::int FROM public.api_pt_receipts rec WHERE rec.assessment_id=$1 AND rec.permit_hash=$2 AND rec.decision='ALLOWED') AS authorized_receipts",
   [String(v.pt_assessment_id),String(v.permit_hash)]);
  if(signed.permitId===undefined||signed.scopeId!==v.stored_permit_scope_id||
     signed.tenantId!==String((await tx.query("SELECT current_setting('api.tenant_id') AS id")).rows[0].id)||
     Number(lineage.rows[0]?.unfinished)!==0||Number(lineage.rows[0]?.authorized_receipts)<1)
    fail("SIGNED_GOVERNED_PT_EVIDENCE_MISSING");
 }catch(error){
  // Reveal only a bounded code to isolated CI, never raw signed bodies, keys or claims.
  if(process.env.NODE_ENV==="test"&&process.env.SYNTHETIC_AUTH_ENABLED==="true"){
   const reason=error instanceof Error?error.message:"UNKNOWN";
   throw new Error("SIGNED_GOVERNED_PT_EVIDENCE_MISSING:"+reason.replace(/[^A-Z0-9_]/gi,"_").slice(0,64));
  }
  fail("SIGNED_GOVERNED_PT_EVIDENCE_MISSING");
 }
 return {fingerprint:fingerprint(JSON.stringify({report:v.report_fingerprint,ptId:v.pt_assessment_id,
   ptFingerprint:v.pt_fingerprint,permitHash:v.permit_hash})),child:String(v.pt_assessment_id),
   type:"SIGNED_GOVERNED_SYNTHETIC_PT",permit:String(v.permit_hash)};
}
export async function reserveObservedReport(t:string,reportId:string,key:string,ttlSeconds=300){
 return reserveFeatureObservation(t,reportId,key,"IMMUTABLE_REPORT_OBSERVED",ttlSeconds);
}
export async function reserveFeatureObservation(t:string,reportId:string,key:string,feature:Feature,ttlSeconds=300){
 if(!features.includes(feature))fail("UNSUPPORTED_FEATURE_OR_VERSION",400);
 if(feature!=="IMMUTABLE_REPORT_OBSERVED"&&(process.env.NODE_ENV!=="test"||process.env.SYNTHETIC_AUTH_ENABLED!=="true"))
  fail("HOST_AUTHORITY_NOT_CONFIGURED",403);

 if(!Number.isSafeInteger(ttlSeconds)||ttlSeconds<1||ttlSeconds>300)fail("INVALID_RESERVATION_TTL",400);
 if(ttlSeconds!==300&&(process.env.NODE_ENV!=="test"||process.env.SYNTHETIC_AUTH_ENABLED!=="true"))fail("HOST_AUTHORITY_NOT_CONFIGURED",403);
 id(t);id(reportId);checkKey(key);
 return withTenant(t,async tx=>{
  await lock(tx,t,feature);
  await tx.query("UPDATE public.api_v13_reservations SET state='EXPIRED' WHERE state='RESERVED' AND expires_at<=clock_timestamp()");
  const old=await tx.query("SELECT * FROM public.api_v13_reservations WHERE idempotency_key=$1",[key]);
  if(old.rowCount){
   if(old.rows[0].source_report_id!==reportId||old.rows[0].feature!==feature)fail("IDEMPOTENCY_CONFLICT");
   return {id:old.rows[0].id,state:old.rows[0].state,replay:true};
  }
  const e=await latest(tx,feature);
  if(!e)return fail("ENTITLEMENT_UNAVAILABLE",403);
  if(e.state!=="ISSUED"||Date.parse(String(e.expires_at))<=Date.now())return fail("ENTITLEMENT_UNAVAILABLE",403);
  const source=await qualifiedSource(tx,reportId,feature);
  const exists=await tx.query("SELECT id FROM public.api_v13_reservations WHERE source_report_id=$1 AND feature=$2 AND state IN ('RESERVED','SETTLED')",[reportId,feature]);
  if(exists.rowCount)fail("SOURCE_ALREADY_ACCOUNTED");
  const m=await month(tx),usage=await totals(tx,m,feature);
  if(usage.consumed+usage.reserved+1>e.limit_units)fail("QUOTA_EXCEEDED",429);
  const reservationId=randomUUID();
  await tx.query("INSERT INTO public.api_v13_reservations(id,tenant_id,entitlement_id,feature,source_report_id,month_start,idempotency_key,units,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,1,clock_timestamp()+$8::int*interval '1 second')",
   [reservationId,t,e.entitlement_id,feature,reportId,m,key,ttlSeconds]);
  if(feature!=="IMMUTABLE_REPORT_OBSERVED")await tx.query("INSERT INTO public.api_v13_feature_sources(id,tenant_id,reservation_id,feature,source_type,source_report_id,source_assessment_id,source_fingerprint,historical_permit_hash,terminal_outcome,entitlement_revision) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'COMPLETED',$10)",[randomUUID(),t,reservationId,feature,source.type,reportId,source.child,source.fingerprint,source.permit,e.revision]);
  return {id:reservationId,state:"RESERVED",replay:false};
 },"phase13-reserve");
}
export async function settleObservedReport(t:string,reservationId:string){
 return settleFeatureObservation(t,reservationId);
}
export async function settleFeatureObservation(t:string,reservationId:string){
 id(t);id(reservationId);
 return withTenant(t,async tx=>{
  const sourceFeature=await tx.query("SELECT feature FROM public.api_v13_reservations WHERE id=$1",[reservationId]);
  if(!sourceFeature.rowCount)fail("RESERVATION_NOT_FOUND",404);
  const feature=sourceFeature.rows[0].feature as Feature;
  await lock(tx,t,feature);
  const q=await tx.query("SELECT * FROM public.api_v13_reservations WHERE id=$1 FOR UPDATE",[reservationId]);
  if(!q.rowCount)fail("RESERVATION_NOT_FOUND",404);
  const r=q.rows[0];
  if(r.state==="SETTLED")return {id:r.id,state:"SETTLED",replay:true};
  if(r.state!=="RESERVED")fail("RESERVATION_ALREADY_CLOSED");
  if(Date.parse(String(r.expires_at))<=Date.now())fail("RESERVATION_EXPIRED");
  const source=await qualifiedSource(tx,r.source_report_id,feature);
  const current=await latest(tx,feature);
  if(feature!=="IMMUTABLE_REPORT_OBSERVED"){
   const attestation=await tx.query("SELECT source_fingerprint,source_assessment_id,historical_permit_hash,entitlement_revision FROM public.api_v13_feature_sources WHERE reservation_id=$1",[r.id]);
   if(attestation.rowCount!==1||attestation.rows[0].source_fingerprint!==source.fingerprint||
     attestation.rows[0].source_assessment_id!==source.child||
     attestation.rows[0].historical_permit_hash!==source.permit||
     Number(attestation.rows[0].entitlement_revision)!==Number(current?.revision))
     fail("SOURCE_FINGERPRINT_OR_ENTITLEMENT_REVISION_MISMATCH");
  }
  if(!current||current.state!=="ISSUED"||Date.parse(String(current.expires_at))<=Date.now())
   fail("ENTITLEMENT_UNAVAILABLE",403);
  const ledgerId=randomUUID();
  await tx.query("UPDATE public.api_v13_reservations SET state='SETTLED',settled_at=clock_timestamp() WHERE id=$1",[r.id]);
  await tx.query("INSERT INTO public.api_v13_usage_ledger(id,tenant_id,reservation_id,feature,source_report_id,month_start,units,source_fingerprint) VALUES($1,$2,$3,$4,$5,$6,$7,$8)",
   [ledgerId,t,r.id,feature,r.source_report_id,r.month_start,r.units,source.fingerprint]);
  await phase13TestFaultBarrier("phase13-settle:between-ledger-outbox");
  await tx.query("INSERT INTO public.api_v13_outbox(id,tenant_id,source_usage_id,payload) VALUES($1,$2,$3,$4::jsonb)",
   [randomUUID(),t,ledgerId,JSON.stringify({schemaVersion:"api-family-commercial-v13",event:"USAGE_OBSERVED",units:r.units,sourceReportId:r.source_report_id,feature,syntheticOnly:true,delivery:"DISABLED"})]);
  return {id:r.id,state:"SETTLED",replay:false};
 },"phase13-settle");
}
export async function closeReservation(t:string,reservationId:string){
 id(t);id(reservationId);
 return withTenant(t,async tx=>{
  const sourceFeature=await tx.query("SELECT feature FROM public.api_v13_reservations WHERE id=$1",[reservationId]);
  if(!sourceFeature.rowCount)fail("RESERVATION_NOT_FOUND",404);
  await lock(tx,t,String(sourceFeature.rows[0].feature));
  const q=await tx.query("SELECT state,expires_at FROM public.api_v13_reservations WHERE id=$1 FOR UPDATE",[reservationId]);
  if(!q.rowCount)fail("RESERVATION_NOT_FOUND",404);
  if(q.rows[0].state!=="RESERVED")return {state:q.rows[0].state};
  const state=Date.parse(String(q.rows[0].expires_at))<=Date.now()?"EXPIRED":"RELEASED";
  await tx.query("UPDATE public.api_v13_reservations SET state=$2 WHERE id=$1",[reservationId,state]);
  return {state};
 },"phase13-close");
}
/** No external snapshot -> PENDING, not a fabricated MATCHED invoice. */
export async function reconcilePending(t:string,feature:Feature=features[0]){
 id(t);
 return withTenant(t,async tx=>{
  await lock(tx,t,feature);
  const m=await month(tx),tot=await totals(tx,m,feature);
  const prior=await tx.query("SELECT id,state,local_units FROM public.api_v13_reconciliation WHERE feature=$2 AND month_start=$1 AND external_revision IS NULL ORDER BY created_at DESC,id DESC LIMIT 1",[m,feature]);
  if(prior.rowCount&&Number(prior.rows[0].local_units)===tot.consumed)return prior.rows[0];
  const rid=randomUUID();
  await tx.query("INSERT INTO public.api_v13_reconciliation(id,tenant_id,feature,month_start,local_units,state) VALUES($1,$2,$3,$4,$5,'PENDING_EXTERNAL_AUTHORITY')",
   [rid,t,feature,m,tot.consumed]);
  return {id:rid,state:"PENDING_EXTERNAL_AUTHORITY"};
 });
}
/** Dedicated CI-only signed corrections; never permit arbitrary client counters or destructive edits. */
export async function ingestSyntheticUsageCorrection(raw:Uint8Array,signature:string,key:Uint8Array){
 const e=verifySyntheticCorrection(raw,signature,key),digest=fingerprint(raw);
 return withTenant(e.tenantId,async tx=>{
  const sourceFeature=await tx.query("SELECT feature FROM public.api_v13_usage_ledger WHERE id=$1",[e.usageId]);
  if(!sourceFeature.rowCount)fail("USAGE_SOURCE_NOT_FOUND",404);
  await lock(tx,e.tenantId,String(sourceFeature.rows[0].feature));
  const old=await tx.query("SELECT id,payload_fingerprint FROM public.api_v13_usage_corrections WHERE correction_id=$1",[e.correctionId]);
  if(old.rowCount){
   if(old.rows[0].payload_fingerprint!==digest)fail("CORRECTION_ID_REUSE_CONFLICT");
   return {id:old.rows[0].id,replay:true};
  }
  const source=await tx.query("SELECT id,units FROM public.api_v13_usage_ledger WHERE id=$1",[e.usageId]);
  if(!source.rowCount)fail("USAGE_SOURCE_NOT_FOUND",404);
  const adjusted=await tx.query("SELECT coalesce(sum(unit_delta),0)::int AS n FROM public.api_v13_usage_corrections WHERE source_usage_id=$1",[e.usageId]);
  const original=Number(source.rows[0].units),effective=original+Number(adjusted.rows[0].n)+e.unitDelta;
  if(effective<0||effective>original)fail("INVALID_USAGE_CORRECTION",409);
  const correctionId=randomUUID();
  await tx.query("INSERT INTO public.api_v13_usage_corrections(id,tenant_id,correction_id,source_usage_id,unit_delta,reason,payload_fingerprint) VALUES($1,$2,$3,$4,$5,$6,$7)",
   [correctionId,e.tenantId,e.correctionId,e.usageId,e.unitDelta,e.reason,digest]);
  return {id:correctionId,replay:false,syntheticOnly:true,effectiveUnits:effective};
 });
}

/** Independently signed CI external fixture; real Host accounting remains unconfigured. */
export async function reconcileSyntheticExternalSnapshot(t:string,raw:Uint8Array,signature:string,key:Uint8Array){
 id(t);
 const s=verifySyntheticExternalSnapshot(raw,signature,key);
 if(s.tenantId!==t)fail("SNAPSHOT_TENANT_MISMATCH",403);
 const digest=fingerprint(raw);
 return withTenant(t,async tx=>{
  await lock(tx,t,s.feature);
  const previous=await tx.query("SELECT id,state,external_revision,external_fingerprint FROM public.api_v13_reconciliation WHERE feature=$1 AND month_start=$2 AND external_revision IS NOT NULL ORDER BY external_revision DESC LIMIT 1",
   [s.feature,s.monthStart]);
  if(previous.rowCount){
   const p=previous.rows[0];
   if(p.external_revision===s.revision){
    if(p.external_fingerprint!==digest)fail("SNAPSHOT_REVISION_CONFLICT");
    return {id:p.id,state:p.state,replay:true};
   }
   if(p.external_revision>s.revision)fail("SNAPSHOT_STALE_REVISION");
  }else if(s.revision!==1)fail("SNAPSHOT_REVISION_CONFLICT");
  const local=await tx.query("SELECT coalesce(sum(units),0)::int AS n FROM public.api_v13_usage_ledger WHERE feature=$1 AND month_start=$2 AND created_at<=$3",
   [s.feature,s.monthStart,s.watermarkAt]);
  const corrected=await tx.query("SELECT coalesce(sum(c.unit_delta),0)::int AS n FROM public.api_v13_usage_corrections c JOIN public.api_v13_usage_ledger l ON l.tenant_id=c.tenant_id AND l.id=c.source_usage_id WHERE l.feature=$1 AND l.month_start=$2 AND l.created_at<=$3 AND c.created_at<=$3",
   [s.feature,s.monthStart,s.watermarkAt]);
  const observed=Number(local.rows[0].n)+Number(corrected.rows[0].n);
  const state=observed===s.observedUnits?"MATCHED":"MISMATCH";
  const id=randomUUID();
  await tx.query("INSERT INTO public.api_v13_reconciliation(id,tenant_id,feature,month_start,external_revision,local_units,external_units,external_fingerprint,state) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)",
   [id,t,s.feature,s.monthStart,s.revision,observed,s.observedUnits,digest,state]);
  return {id,state,replay:false,syntheticExternalOnly:true};
 });
}

export function registerPhase13Routes(app:FastifyInstance,identity:(req:FastifyRequest)=>string){
 app.get("/v13/capabilities",async()=>({schemaVersion:"api-family-commercial-v13",syntheticOnly:true,
  productionHostIntegration:false,hostAuthority:"HOST_AUTHORITY_NOT_CONFIGURED",
  meterDefinitions:commercialFeatureCatalog.map(x=>({feature:x.feature,version:x.version,unit:x.evidence,billable:false,syntheticOnly:true})),
  featureDefinitions:commercialFeatureCatalog,
  scanningAuthority:false,verifiedFixedAuthority:false}));
 app.get("/v13/entitlements",async req=>({projection:await projection(identity(req))}));
 app.get("/v13/usage/summary",async req=>projection(identity(req)));
 app.get("/v13/usage/events",async req=>{
  const t=identity(req),p=page(req);
  return withTenant(t,async tx=>(await tx.query("SELECT id,feature,source_report_id AS \"sourceReportId\",units,source_fingerprint AS \"sourceFingerprint\",created_at AS \"createdAt\" FROM public.api_v13_usage_ledger ORDER BY created_at DESC,id DESC LIMIT $1 OFFSET $2",[p.n,p.o])).rows);
 });
 app.get("/v13/usage/corrections",async req=>{
  const t=identity(req),p=page(req);
  return withTenant(t,async tx=>(await tx.query("SELECT id,source_usage_id AS \"sourceUsageId\",unit_delta AS \"unitDelta\",reason,created_at AS \"createdAt\" FROM public.api_v13_usage_corrections ORDER BY created_at DESC,id DESC LIMIT $1 OFFSET $2",[p.n,p.o])).rows);
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
  let n=1;
  try{n=unit(q.quantity===undefined?1:Number(q.quantity));}catch{fail("INVALID_QUANTITY",400);}
  const summary=await projection(identity(req));
  return {allowed:false,code:"HOST_AUTHORITY_NOT_CONFIGURED",syntheticProjectionWouldAllow:
   summary.entitlement?.state==="ISSUED"&&n>0&&summary.remaining>=n,quantity:n,
   warning:"Commercial projection cannot grant production operation or PT authority"};
 });
}
