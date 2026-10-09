import type {FastifyInstance,FastifyRequest} from "fastify";
import {createHash} from "node:crypto";
import {withTenant,uuid} from "../../database/src/index.js";
import {compareInventory,DiscoveryError,type Inventory} from "../../discovery/src/index.js";
import {importOfflineIsolated} from "../../discovery/src/isolated.js";
export class ImportError extends Error {constructor(public statusCode:number,public code:string){super(code);}}
const fail=(n:number,code:string):never=>{throw new ImportError(n,code);};
const guid=(value:unknown):string=>typeof value==="string"&&/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i.test(value)?value:fail(400,"INVALID_IDENTIFIER");
const body=(x:unknown):Record<string,unknown>=>x&&typeof x==="object"&&!Array.isArray(x)?x as Record<string,unknown>:fail(400,"INVALID_BODY");
const query=(req:FastifyRequest)=>req.query as Record<string,unknown>;
const bounded=(v:unknown,d:number,max:number):number=>{if(v===undefined)return d;const n=Number(v);if(!Number.isSafeInteger(n)||n<0||n>max)fail(400,"INVALID_PAGINATION");return n;};
const sha=(value:string)=>createHash("sha256").update(value).digest("hex");
function scrubPostman(text:string):string {
 let root:unknown;try{root=JSON.parse(text);}catch{return "{}";}
 const scrub=(x:unknown):unknown=>{
  if(Array.isArray(x))return x.map(scrub);if(!x||typeof x!=="object")return x;
  const o:Record<string,unknown>={};
  for(const [key,value] of Object.entries(x)){
   if(["event","script"].includes(key))continue;
   if(["token","password","secret","clientSecret","access_token","refresh_token","value","raw"].includes(key)){
    o[key]="[REDACTED]";continue;
   }
   if(key==="auth"){o[key]={type:typeof value==="object"?((value as Record<string,unknown>).type??"unknown"):"unknown"};continue;}
   if(key==="header"){o[key]=[];continue;}
   if(key==="body"){o[key]={mode:typeof value==="object"?((value as Record<string,unknown>).mode??"unknown"):"unknown"};continue;}
   o[key]=scrub(value);
  }
  return o;
 };
 return JSON.stringify(scrub(root));
}
function params(req:FastifyRequest):{id:string;specId:string}{
 const p=req.params as Record<string,unknown>;return {id:guid(p.id),specId:p.specId===undefined?"":guid(p.specId)};
}
function rowView(row:Record<string,unknown>){return {id:row.id,targetId:row.target_id,specificationId:row.specification_id,status:row.status,errorCode:row.error_code,rawFingerprint:row.fingerprint,receivedAt:row.received_at,completedAt:row.completed_at};}
const codeFrom=(e:unknown)=>e instanceof DiscoveryError?e.code:"DOCUMENT_VALIDATION_FAILED";
export async function registerDiscoveryRoutes(app:FastifyInstance,tenant:(req:FastifyRequest)=>string):Promise<void>{
 app.post("/v2/targets/:id/specifications/imports",async(req,reply)=>{
  const {id:targetId}=params(req),t=tenant(req),b=body(req.body),key=req.headers["idempotency-key"];
  if(typeof key!=="string"||!/^[a-zA-Z0-9:_-]{8,128}$/.test(key))fail(400,"IDEMPOTENCY_KEY_REQUIRED");
  const name=b.filename,content=b.content;
  if(typeof name!=="string"||!/^[A-Za-z0-9_.-]{1,120}\.(?:json|ya?ml)$/i.test(name)||typeof content!=="string")fail(400,"INVALID_DOCUMENT_UPLOAD");
  if(Buffer.byteLength(content as string,"utf8")>1048576)fail(413,"DOCUMENT_SIZE_LIMIT");
  const fingerprint=sha(content as string);
  const result=await withTenant(t,async tx=>{
   const target=await tx.query("SELECT id,lifecycle FROM api_targets WHERE id=$1 FOR UPDATE",[targetId]);
   if(!target.rowCount)fail(404,"TARGET_NOT_FOUND");
   if(target.rows[0].lifecycle!=="ACTIVE")fail(409,"TARGET_NOT_ACTIVE");
   const existing=await tx.query("SELECT * FROM api_spec_imports WHERE target_id=$1 AND idempotency_key=$2",[targetId,key]);
   if(existing.rowCount){
    if(existing.rows[0].fingerprint!==fingerprint)fail(409,"IDEMPOTENCY_CONFLICT");
    return {view:rowView(existing.rows[0]),replayed:true};
   }
   const importId=uuid();
   await tx.query("INSERT INTO api_spec_imports(id,tenant_id,target_id,idempotency_key,fingerprint,status) VALUES($1,$2,$3,$4,$5,'RECEIVED')",[importId,t,targetId,key,fingerprint]);
   const log=async(status:string,errorCode:string|null=null)=>tx.query("INSERT INTO api_spec_import_events(id,tenant_id,import_id,state,code) VALUES($1,$2,$3,$4,$5)",[uuid(),t,importId,status,errorCode]);
   await log("RECEIVED");
   await tx.query("UPDATE api_spec_imports SET status='VALIDATING' WHERE id=$1",[importId]);await log("VALIDATING");
   let inventory:Inventory;
   try{inventory=await importOfflineIsolated(content as string);}
   catch(e){
    const errorCode=codeFrom(e).slice(0,90);
    await tx.query("UPDATE api_spec_imports SET status='FAILED',error_code=$2,completed_at=now() WHERE id=$1",[importId,errorCode]);
    await log("FAILED",errorCode);
    return {view:{id:importId,targetId,specificationId:null,status:"FAILED",errorCode,rawFingerprint:fingerprint},replayed:false};
   }
   await tx.query("UPDATE api_spec_imports SET status='NORMALIZING' WHERE id=$1",[importId]);await log("NORMALIZING");
   const match=await tx.query("SELECT * FROM api_spec_inventories WHERE target_id=$1 AND raw_fingerprint=$2",[targetId,fingerprint]);
   if(match.rowCount){
    await tx.query("UPDATE api_spec_imports SET status='COMPLETED',specification_id=$2,completed_at=now() WHERE id=$1",[importId,match.rows[0].specification_id]);
    await log("COMPLETED");
    return {view:{id:importId,targetId,specificationId:match.rows[0].specification_id,status:"COMPLETED",version:match.rows[0].version_number,rawFingerprint:fingerprint,deduplicated:true,format:inventory.format},replayed:false};
   }
   const version=(await tx.query("SELECT COALESCE(MAX(version_number),0)+1 AS next FROM api_spec_inventories WHERE target_id=$1",[targetId])).rows[0].next as number;
   const specificationId=uuid(),raw=inventory.format==="POSTMAN_2_1"?scrubPostman(content as string):content;
   await tx.query("INSERT INTO api_specifications(id,tenant_id,target_id,filename,format,fingerprint,raw_spec) VALUES($1,$2,$3,$4,$5,$6,$7)",[specificationId,t,targetId,name,inventory.format,inventory.rawFingerprint,raw]);
   for(const op of inventory.operations){
    await tx.query("INSERT INTO api_operations(id,tenant_id,specification_id,operation_key,method,path,operation_id,pointer,security_json) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb)",[uuid(),t,specificationId,op.key,op.method,op.path,op.operationId,op.pointer,JSON.stringify(op.auth.requirements)]);
   }
   await tx.query("INSERT INTO api_spec_inventories(specification_id,tenant_id,target_id,version_number,original_format,raw_fingerprint,normalized_fingerprint,normalization_version,snapshot,assessment_source,coverage,selected) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,$11,$12)",
     [specificationId,t,targetId,version,inventory.format,inventory.rawFingerprint,inventory.normalizedFingerprint,inventory.normalizationVersion,JSON.stringify({...inventory,assessmentSource:undefined}),inventory.assessmentSource,inventory.metadata.coverage,version===1&&inventory.assessmentSource!==null]);
   for(const op of inventory.operations){
    await tx.query("INSERT INTO api_inventory_operations(id,tenant_id,specification_id,operation_key,method,path,auth_state,tags,pointer,projection) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb)",
      [uuid(),t,specificationId,op.key,op.method,op.path,op.auth.state,op.tags,op.pointer,JSON.stringify(op)]);
   }
   if(version>1){
    const prev=await tx.query("SELECT specification_id,snapshot FROM api_spec_inventories WHERE target_id=$1 AND version_number=$2",[targetId,version-1]);
    if(prev.rowCount){
      const diff=compareInventory(prev.rows[0].snapshot as Inventory,inventory);
      await tx.query("INSERT INTO api_spec_diffs(id,tenant_id,target_id,from_specification,to_specification,projection) VALUES($1,$2,$3,$4,$5,$6::jsonb)",
        [uuid(),t,targetId,prev.rows[0].specification_id,specificationId,JSON.stringify(diff)]);
    }
   }
   await tx.query("UPDATE api_spec_imports SET status='COMPLETED',specification_id=$2,completed_at=now() WHERE id=$1",[importId,specificationId]);
   await log("COMPLETED");
   await tx.query("INSERT INTO api_audit(id,tenant_id,action,subject_id) VALUES($1,$2,'DISCOVERY_SPEC_IMPORTED',$3)",[uuid(),t,specificationId]);
   return {view:{id:importId,targetId,specificationId,status:"COMPLETED",version,rawFingerprint:fingerprint,format:inventory.format,
     normalizedFingerprint:inventory.normalizedFingerprint,operationCount:inventory.operations.length,coverage:inventory.metadata.coverage,
     assessmentEligible:inventory.assessmentSource!==null,deduplicated:false},replayed:false};
  });
  reply.code(result.view.status==="FAILED"?422:result.replayed?200:201).send(result.view);
 });
 app.get("/v2/targets/:id/specifications/imports",async req=>{
  const {id:targetId}=params(req),t=tenant(req),p=query(req),limit=bounded(p.limit,25,100),offset=bounded(p.offset,0,1000000);
  return withTenant(t,async tx=>{
   if(!(await tx.query("SELECT id FROM api_targets WHERE id=$1",[targetId])).rowCount)fail(404,"TARGET_NOT_FOUND");
   return (await tx.query("SELECT * FROM api_spec_imports WHERE target_id=$1 ORDER BY received_at DESC,id DESC LIMIT $2 OFFSET $3",[targetId,limit,offset])).rows.map(rowView);
  });
 });
 app.get("/v2/targets/:id/specifications/imports/:importId",async req=>{
  const {id:targetId}=params(req),importId=guid((req.params as Record<string,unknown>).importId),t=tenant(req);
  return withTenant(t,async tx=>{
   const found=await tx.query("SELECT * FROM api_spec_imports WHERE target_id=$1 AND id=$2",[targetId,importId]);
   if(!found.rowCount)fail(404,"IMPORT_NOT_FOUND");
   const events=await tx.query("SELECT state,code,occurred_at AS \"occurredAt\" FROM api_spec_import_events WHERE import_id=$1 ORDER BY CASE state WHEN 'RECEIVED' THEN 1 WHEN 'VALIDATING' THEN 2 WHEN 'NORMALIZING' THEN 3 ELSE 4 END,occurred_at,id",[importId]);
   return {...rowView(found.rows[0]),events:events.rows};
  });
 });
 app.get("/v2/targets/:id/specifications",async req=>{
  const {id:targetId}=params(req),t=tenant(req),p=query(req),limit=bounded(p.limit,25,100),offset=bounded(p.offset,0,1000000);
  return withTenant(t,async tx=>{
   if(!(await tx.query("SELECT id FROM api_targets WHERE id=$1",[targetId])).rowCount)fail(404,"TARGET_NOT_FOUND");
   return (await tx.query('SELECT specification_id AS "specificationId",version_number AS version,original_format AS format,raw_fingerprint AS "rawFingerprint",normalized_fingerprint AS "normalizedFingerprint",coverage,selected,(assessment_source IS NOT NULL) AS "assessmentEligible",imported_at AS "importedAt" FROM api_spec_inventories WHERE target_id=$1 ORDER BY version_number DESC LIMIT $2 OFFSET $3',[targetId,limit,offset])).rows;
  });
 });
 app.get("/v2/specifications/:specId",async req=>{
  const specId=guid((req.params as Record<string,unknown>).specId),t=tenant(req);
  return withTenant(t,async tx=>{
   const r=await tx.query("SELECT specification_id,target_id,version_number,original_format,raw_fingerprint,normalized_fingerprint,snapshot,coverage,selected,(assessment_source IS NOT NULL) AS eligible,imported_at FROM api_spec_inventories WHERE specification_id=$1",[specId]);
   if(!r.rowCount)fail(404,"SPECIFICATION_NOT_FOUND");
   const row=r.rows[0];return {specificationId:row.specification_id,targetId:row.target_id,version:row.version_number,format:row.original_format,
    rawFingerprint:row.raw_fingerprint,normalizedFingerprint:row.normalized_fingerprint,coverage:row.coverage,selected:row.selected,
    assessmentEligible:row.eligible,metadata:(row.snapshot as Inventory).metadata,schemes:(row.snapshot as Inventory).schemes,importedAt:row.imported_at};
  });
 });
 app.get("/v2/specifications/:specId/operations",async req=>{
  const specId=guid((req.params as Record<string,unknown>).specId),t=tenant(req),p=query(req);
  const limit=bounded(p.limit,50,100),offset=bounded(p.offset,0,1000000);
  if(!(await withTenant(t,async tx=>(await tx.query("SELECT 1 FROM api_spec_inventories WHERE specification_id=$1",[specId])).rowCount)))fail(404,"SPECIFICATION_NOT_FOUND");
  const method=p.method===undefined?null:String(p.method).toUpperCase(),search=p.search===undefined?"":String(p.search);
  const auth=p.auth===undefined?null:String(p.auth),tag=p.tag===undefined?null:String(p.tag);
  if((method&&!["GET","HEAD","POST","PUT","PATCH","DELETE","OPTIONS","TRACE"].includes(method))||
   (auth&&!["DECLARED","INHERITED","OVERRIDDEN","EXPLICIT_NONE","UNDECLARED","UNKNOWN"].includes(auth))||search.length>120||(tag&&tag.length>100))fail(400,"INVALID_OPERATION_FILTER");
  return withTenant(t,async tx=>(await tx.query('SELECT projection FROM api_inventory_operations WHERE specification_id=$1 AND ($2::text IS NULL OR method=$2) AND ($3::text IS NULL OR auth_state=$3) AND ($4::text=\'\' OR strpos(lower(path),lower($4))>0 OR strpos(lower(operation_key),lower($4))>0) AND ($5::text IS NULL OR $5=ANY(tags)) ORDER BY operation_key LIMIT $6 OFFSET $7',[specId,method,auth,search,tag,limit,offset])).rows.map(x=>x.projection));
 });
 app.get("/v2/specifications/:specId/operations/:operationKey",async req=>{
  const p=req.params as Record<string,unknown>,specId=guid(p.specId),key=String(p.operationKey);
  if(key.length>250)fail(400,"INVALID_OPERATION_KEY");
  return withTenant(tenant(req),async tx=>{
   const r=await tx.query("SELECT projection FROM api_inventory_operations WHERE specification_id=$1 AND operation_key=$2",[specId,key]);
   if(!r.rowCount)fail(404,"OPERATION_NOT_FOUND");
   return r.rows[0].projection;
  });
 });
 app.get("/v2/specifications/:specId/schemes",async req=>{
  const specId=guid((req.params as Record<string,unknown>).specId);
  return withTenant(tenant(req),async tx=>{
   const r=await tx.query("SELECT snapshot FROM api_spec_inventories WHERE specification_id=$1",[specId]);
   if(!r.rowCount)fail(404,"SPECIFICATION_NOT_FOUND");
   return (r.rows[0].snapshot as Inventory).schemes;
  });
 });
 app.get("/v2/specifications/:specId/coverage",async req=>{
  const specId=guid((req.params as Record<string,unknown>).specId);
  return withTenant(tenant(req),async tx=>{
   const r=await tx.query("SELECT snapshot,assessment_source FROM api_spec_inventories WHERE specification_id=$1",[specId]);
   if(!r.rowCount)fail(404,"SPECIFICATION_NOT_FOUND");
   const snapshot=r.rows[0].snapshot as Inventory;
   return {format:snapshot.format,coverage:snapshot.metadata.coverage,warnings:snapshot.metadata.warnings,assessmentEligible:r.rows[0].assessment_source!==null,limitation:"Offline declaration-only. UNKNOWN != SAFE; not runtime endpoint discovery."};
  });
 });
 app.post("/v2/targets/:id/specifications/compare",async req=>{
  const {id:targetId}=params(req),b=body(req.body),a=guid(b.fromSpecificationId),z=guid(b.toSpecificationId),t=tenant(req);
  if(a===z)fail(400,"SAME_VERSION");
  return withTenant(t,async tx=>{
   const rows=await tx.query("SELECT specification_id,snapshot FROM api_spec_inventories WHERE target_id=$1 AND specification_id IN($2,$3)",[targetId,a,z]);
   if(rows.rowCount!==2)fail(404,"SPECIFICATION_NOT_FOUND");
   const prev=rows.rows.find(x=>x.specification_id===a),next=rows.rows.find(x=>x.specification_id===z);
   const diff=compareInventory(prev.snapshot as Inventory,next.snapshot as Inventory);
   await tx.query("INSERT INTO api_spec_diffs(id,tenant_id,target_id,from_specification,to_specification,projection) VALUES($1,$2,$3,$4,$5,$6::jsonb) ON CONFLICT(tenant_id,from_specification,to_specification) DO NOTHING",[uuid(),t,targetId,a,z,JSON.stringify(diff)]);
   return diff;
  });
 });
 app.post("/v2/targets/:id/specifications/:specId/select",async req=>{
  const {id:targetId,specId}=params(req),b=body(req.body),t=tenant(req),expected=b.expectedSelectedId;
  if(expected!==null&&expected!==undefined)guid(expected);
  return withTenant(t,async tx=>{
   const target=await tx.query("SELECT lifecycle FROM api_targets WHERE id=$1 FOR UPDATE",[targetId]);
   if(!target.rowCount)fail(404,"TARGET_NOT_FOUND");
   if(target.rows[0].lifecycle!=="ACTIVE")fail(409,"TARGET_NOT_ACTIVE");
   const r=await tx.query("SELECT specification_id,assessment_source FROM api_spec_inventories WHERE target_id=$1 AND specification_id=$2",[targetId,specId]);
   if(!r.rowCount)fail(404,"SPECIFICATION_NOT_FOUND");
   if(r.rows[0].assessment_source===null)fail(409,"FORMAT_NOT_ELIGIBLE_FOR_LEGACY_ASSESSMENT");
   const current=await tx.query("SELECT specification_id FROM api_spec_inventories WHERE target_id=$1 AND selected=true",[targetId]);
   const selected=current.rows[0]?.specification_id??null;
   if(selected!==(expected??null))fail(409,"STALE_SELECTED_VERSION");
   await tx.query("UPDATE api_spec_inventories SET selected=false WHERE target_id=$1 AND selected=true",[targetId]);
   await tx.query("UPDATE api_spec_inventories SET selected=true WHERE target_id=$1 AND specification_id=$2",[targetId,specId]);
   await tx.query("INSERT INTO api_audit(id,tenant_id,action,subject_id) VALUES($1,$2,'SPEC_VERSION_SELECTED',$3)",[uuid(),t,specId]);
   return {targetId,selectedSpecificationId:specId,assessmentMode:"SPEC_ONLY",networkRequestsAuthorized:0};
  });
 });
}
