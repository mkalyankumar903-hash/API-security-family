/** Phase12 report workflow metadata. This module does NOT import execution or permit authority. */
import type {FastifyInstance,FastifyRequest} from "fastify";
import {withTenant,uuid} from "../../database/src/index.js";
import {PtError} from "./pt.js";
import {presentVaptReport} from "./phase12.js";
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const KEY=/^[0-9a-f]{64}$/;
const states=["NEEDS_REVIEW","INVESTIGATING","REMEDIATION_PLANNED","FIX_CLAIMED",
 "DEFERRED","ACCEPTED_FOR_REVIEW"] as const;
const id=(v:unknown)=>{if(typeof v!=="string"||!UUID.test(v))throw new PtError(400,"INVALID_ID");return v;};
const route=(r:FastifyRequest,name="id")=>id((r.params as Record<string,unknown>)[name]);
const body=(v:unknown,keys:string[])=>{
 if(!v||typeof v!=="object"||Array.isArray(v))throw new PtError(400,"INVALID_BODY");
 const b=v as Record<string,unknown>;
 if(Object.keys(b).some(k=>!keys.includes(k)))throw new PtError(400,"UNKNOWN_FIELD");
 return b;
};
const pos=(n:unknown,d:number,max:number)=>{
 const value=n===undefined?d:Number(n);
 if(!Number.isSafeInteger(value)||value<1||value>max)throw new PtError(400,"INVALID_PAGINATION");
 return value;
};
const pagination=(r:FastifyRequest)=>{
 const q=(r.query??{}) as Record<string,unknown>;
 if(Object.keys(q).some(k=>!["limit","offset"].includes(k)))throw new PtError(400,"INVALID_FILTER");
 const limit=pos(q.limit,30,100),offset=q.offset===undefined?0:Number(q.offset);
 if(!Number.isSafeInteger(offset)||offset<0||offset>100000)throw new PtError(400,"INVALID_PAGINATION");
 return {limit,offset};
};
const reject=(code:string,status=409):never=>{throw new PtError(status,code);};
async function authorizedReport(tx:import("pg").PoolClient,reportId:string){
 const r=await tx.query("SELECT id FROM public.api_vapt11_reports WHERE parent_assessment_id=$1",[reportId]);
 if(!r.rowCount)reject("REPORT_NOT_FOUND_OR_NOT_READY",404);
 return r.rows[0].id as string;
}
async function log(tx:import("pg").PoolClient,tenant:string,reportId:string,action:string,subject:string|null=null){
 await tx.query("INSERT INTO public.api_v12_report_audit(id,tenant_id,parent_assessment_id,action,subject_id) VALUES($1,$2,$3,$4,$5)",
  [uuid(),tenant,reportId,action,subject]);
}
export function registerPhase12WorkflowRoutes(app:FastifyInstance,identity:(req:FastifyRequest)=>string){
 app.get("/v12/reports/:id/annotations",async req=>{
  const t=identity(req),rid=route(req),p=pagination(req);
  return withTenant(t,async tx=>{
   await authorizedReport(tx,rid);
   return (await tx.query(
    "SELECT stable_key,version,state,note,actor_context,created_at FROM public.api_v12_annotations "+
    "WHERE parent_assessment_id=$1 ORDER BY created_at DESC,id DESC LIMIT $2 OFFSET $3",
    [rid,p.limit,p.offset])).rows;
  });
 });
 app.post("/v12/reports/:id/annotations",async req=>{
  const t=identity(req),rid=route(req),b=body(req.body,["stableKey","state","note","expectedVersion"]);
  if(typeof b.stableKey!=="string"||!KEY.test(b.stableKey))reject("INVALID_FINDING_REFERENCE",400);
  if(typeof b.state!=="string"||!states.includes(b.state as typeof states[number]))reject("INVALID_ANNOTATION_STATE",400);
  const note=b.note===undefined?"":b.note;
  if(typeof note!=="string"||note.length>1000)reject("INVALID_ANNOTATION_NOTE",400);
  const v=b.expectedVersion;
  if(!Number.isSafeInteger(v)||Number(v)<0||Number(v)>999999)reject("INVALID_EXPECTED_VERSION",400);
  return withTenant(t,async tx=>{
   await authorizedReport(tx,rid);
   await tx.query("SELECT pg_advisory_xact_lock(hashtext($1),hashtext($2))",[t,rid+":"+b.stableKey]);
   const exists=await tx.query("SELECT 1 FROM public.api_vapt11_correlations WHERE parent_assessment_id=$1 AND stable_key=$2",
    [rid,b.stableKey]);
   if(!exists.rowCount)reject("FINDING_NOT_FOUND",404);
   const current=await tx.query("SELECT coalesce(max(version),0)::int AS version FROM public.api_v12_annotations WHERE parent_assessment_id=$1 AND stable_key=$2",
    [rid,b.stableKey]);
   const previous=current.rows[0].version as number;
   if(previous!==v)reject("ANNOTATION_VERSION_CONFLICT");
   const row=await tx.query("INSERT INTO public.api_v12_annotations(id,tenant_id,parent_assessment_id,stable_key,version,state,note) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING stable_key,version,state,note,created_at",
    [uuid(),t,rid,b.stableKey,previous+1,b.state,note]);
   await log(tx,t,rid,"ANNOTATION_ADDED");
   return {...row.rows[0],immutableSecurityEvidenceUnchanged:true,verifiedFixed:false};
  });
 });
 app.get("/v12/branding",async req=>withTenant(identity(req),async tx=>{
  const r=await tx.query("SELECT display_name AS \"displayName\",report_title AS \"reportTitle\",accent_hex AS \"accentHex\",version,updated_at AS \"updatedAt\" FROM public.api_v12_branding");
  return r.rows[0]??{displayName:"Organization",reportTitle:"API Security Report",accentHex:"#2457A7",version:0};
 }));
 app.put("/v12/branding",async req=>{
  const t=identity(req),b=body(req.body,["displayName","reportTitle","accentHex","expectedVersion"]);
  if(typeof b.displayName!=="string"||b.displayName.length<1||b.displayName.length>100||
     /^lumicsec(\b|\s|$)/i.test(b.displayName))reject("INVALID_BRANDING_NAME",400);
  if(typeof b.reportTitle!=="string"||b.reportTitle.length<1||b.reportTitle.length>120)
   reject("INVALID_BRANDING_TITLE",400);
  if(typeof b.accentHex!=="string"||!/^#[a-fA-F0-9]{6}$/.test(b.accentHex))
   reject("INVALID_BRANDING_COLOR",400);
  if(!Number.isInteger(b.expectedVersion)||Number(b.expectedVersion)<0||Number(b.expectedVersion)>999999)
   reject("INVALID_BRANDING_VERSION",400);
  return withTenant(t,async tx=>{
   const previous=await tx.query("SELECT version FROM public.api_v12_branding WHERE tenant_id=$1 FOR UPDATE",[t]);
   const ver=previous.rows[0]?.version??0;
   if(ver!==b.expectedVersion)reject("BRANDING_VERSION_CONFLICT");
   const updated=previous.rowCount?
    await tx.query("UPDATE public.api_v12_branding SET display_name=$2,report_title=$3,accent_hex=$4,version=version+1,updated_at=clock_timestamp() WHERE tenant_id=$1 RETURNING version",
     [t,b.displayName,b.reportTitle,b.accentHex]):
    await tx.query("INSERT INTO public.api_v12_branding(tenant_id,display_name,report_title,accent_hex) VALUES($1,$2,$3,$4) RETURNING version",
     [t,b.displayName,b.reportTitle,b.accentHex]);
   await tx.query("INSERT INTO public.api_audit(id,tenant_id,action,subject_id) VALUES($1,$2,'PHASE12_BRANDING_UPDATED',$2)",[uuid(),t]);
   return {displayName:b.displayName,reportTitle:b.reportTitle,accentHex:b.accentHex,
    version:updated.rows[0].version,findingsModified:false};
  });
 });
 app.post("/v12/reports/:id/shares",async req=>{
  const t=identity(req),rid=route(req),b=body(req.body,["durationSeconds"]);
  const seconds=pos(b.durationSeconds,3600,86400);
  if(seconds<300)reject("SHARE_LIFETIME_TOO_SHORT",400);
  const key=req.headers["idempotency-key"];
  if(typeof key!=="string"||!/^[a-zA-Z0-9:_-]{8,128}$/.test(key))reject("IDEMPOTENCY_KEY_REQUIRED",400);
  return withTenant(t,async tx=>{
   await authorizedReport(tx,rid);
   await tx.query("SELECT pg_advisory_xact_lock(hashtext($1),hashtext($2))",[t,key]);
   const previous=await tx.query("SELECT id,parent_assessment_id,duration_seconds,expires_at,revoked_at FROM public.api_v12_shares WHERE idempotency_key=$1",[key]);
   if(previous.rowCount){
    const old=previous.rows[0];
    if(old.parent_assessment_id!==rid||old.duration_seconds!==seconds)reject("SHARE_IDEMPOTENCY_CONFLICT");
    return {shareId:old.id,expiresAt:old.expires_at,revoked:!!old.revoked_at,
     authorization:"TENANT_AUTHENTICATED_ONLY",created:false};
   }
   const sid=uuid();
   const created=await tx.query("INSERT INTO public.api_v12_shares(id,tenant_id,parent_assessment_id,idempotency_key,duration_seconds,expires_at) VALUES($1,$2,$3,$4,$5,clock_timestamp()+($5::integer * interval '1 second')) RETURNING expires_at",
    [sid,t,rid,key,seconds]);
   await log(tx,t,rid,"SHARE_CREATED",sid);
   return {shareId:sid,expiresAt:created.rows[0].expires_at,revoked:false,
    authorization:"TENANT_AUTHENTICATED_ONLY",created:true};
  });
 });
 app.get("/v12/reports/:id/shares",async req=>{
  const t=identity(req),rid=route(req),p=pagination(req);
  return withTenant(t,async tx=>{
   await authorizedReport(tx,rid);
   return (await tx.query("SELECT id AS \"shareId\",created_at AS \"createdAt\",expires_at AS \"expiresAt\",revoked_at AS \"revokedAt\" FROM public.api_v12_shares WHERE parent_assessment_id=$1 ORDER BY created_at DESC,id DESC LIMIT $2 OFFSET $3",
    [rid,p.limit,p.offset])).rows;
  });
 });
 app.get("/v12/shares/:id",async req=>{
  const t=identity(req),sid=route(req);
  return withTenant(t,async tx=>{
   const share=await tx.query("SELECT parent_assessment_id FROM public.api_v12_shares WHERE id=$1 AND revoked_at IS NULL AND expires_at>clock_timestamp() FOR SHARE",[sid]);
   if(!share.rowCount)reject("SHARE_UNAVAILABLE",404);
   const rid=share.rows[0].parent_assessment_id;
   const row=await tx.query("SELECT id,parent_assessment_id,fingerprint,created_at,projection FROM public.api_vapt11_reports WHERE parent_assessment_id=$1",[rid]);
   if(!row.rowCount)reject("REPORT_UNAVAILABLE",404);
   const x=row.rows[0];
   const report=presentVaptReport(x.projection,{id:x.id,assessmentId:x.parent_assessment_id,
    fingerprint:x.fingerprint,createdAt:new Date(x.created_at).toISOString()});
   await log(tx,t,rid,"SHARE_VIEWED",sid);
   return {...report,shareAuthorization:"CURRENT_TENANT_BEARER_REQUIRED"};
  });
 });
 app.post("/v12/shares/:id/revoke",async req=>{
  const t=identity(req),sid=route(req);
  return withTenant(t,async tx=>{
   const found=await tx.query("SELECT parent_assessment_id,revoked_at FROM public.api_v12_shares WHERE id=$1 FOR UPDATE",[sid]);
   if(!found.rowCount)reject("SHARE_NOT_FOUND",404);
   const rid=found.rows[0].parent_assessment_id;
   if(!found.rows[0].revoked_at){
    await tx.query("UPDATE public.api_v12_shares SET revoked_at=clock_timestamp() WHERE id=$1",[sid]);
    await log(tx,t,rid,"SHARE_REVOKED",sid);
   }
   return {shareId:sid,revoked:true,authorizationExpansion:false};
  });
 });
 app.get("/v12/reports/:id/audit",async req=>{
  const t=identity(req),rid=route(req),p=pagination(req);
  return withTenant(t,async tx=>{
   await authorizedReport(tx,rid);
   return (await tx.query("SELECT action,subject_id,created_at FROM public.api_v12_report_audit WHERE parent_assessment_id=$1 ORDER BY created_at DESC,id DESC LIMIT $2 OFFSET $3",
    [rid,p.limit,p.offset])).rows;
  });
 });
}
