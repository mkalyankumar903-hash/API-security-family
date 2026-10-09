import type {FastifyInstance,FastifyRequest} from "fastify";
import {withTenant,uuid} from "../../database/src/index.js";
import {RULE_CATALOG,INVENTORY_ENGINE_VERSION,compareDetection,type DetectionResult} from "../../assessment-engine/src/inventory.js";
import type {Inventory} from "../../discovery/src/index.js";

// Reuses existing synthetic test identity, tenant-scoped transaction, private queue and immutable Phase 02 inventory.
// No separate Host authority, network permit, target request, user-controlled rule code or background queue exists here.
export class DetectionError extends Error {constructor(public statusCode:number,public code:string){super(code);}}
const fail=(n:number,c:string):never=>{throw new DetectionError(n,c);};
const id=(s:unknown)=>typeof s==="string"&&/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i.test(s)?s:fail(400,"INVALID_IDENTIFIER");
const body=(x:unknown)=>x&&typeof x==="object"&&!Array.isArray(x)?x as Record<string,unknown>:fail(400,"INVALID_BODY");
const page=(req:FastifyRequest)=>{const q=req.query as Record<string,unknown>;const limit=q.limit===undefined?25:Number(q.limit),offset=q.offset===undefined?0:Number(q.offset);
 if(!Number.isInteger(limit)||limit<1||limit>100||!Number.isSafeInteger(offset)||offset<0||offset>1000000)fail(400,"INVALID_PAGINATION");
 return {limit,offset};};
const part=(req:FastifyRequest,name:string)=>id((req.params as Record<string,unknown>)[name]);
export async function registerDetectionRoutes(app:FastifyInstance,tenant:(req:FastifyRequest)=>string):Promise<void> {
 app.get("/v3/detection/engines",async()=>[{id:INVENTORY_ENGINE_VERSION,mode:"SPEC_ONLY",normalization:"phase02-v1",networkRequestsAuthorized:0,methods:[]}]);
 app.get("/v3/detection/capabilities",async()=>({engine:INVENTORY_ENGINE_VERSION,mode:"SPEC_ONLY",
  formats:["OPENAPI_3_0","OPENAPI_3_1","SWAGGER_2","POSTMAN_2_1"],rules: RULE_CATALOG.length,
  supportedRules:RULE_CATALOG.filter(r=>!r.unsupported).length,networkRequestsAuthorized:0,
  limitations:["No runtime testing or authenticated probing","Unknown does not mean safe","Unsupported rules and format gaps are explicit."]}));
 app.get("/v3/detection/rules",async req=>{const p=page(req);return RULE_CATALOG.slice(p.offset,p.offset+p.limit).map(r=>({...r,availability:r.unsupported?"UNSUPPORTED":"DECLARATION_ONLY"}));});
 app.get("/v3/detection/rules/:ruleId",async req=>{const found=RULE_CATALOG.find(r=>r.id===(req.params as Record<string,unknown>).ruleId);
  if(!found)throw new DetectionError(404,"RULE_NOT_FOUND");return {...found,availability:found.unsupported?"UNSUPPORTED":"DECLARATION_ONLY"};});
 app.post("/v3/targets/:id/assessments",async(req,reply)=>{
  const targetId=part(req,"id"),b=body(req.body),specificationId=id(b.specificationId);
  if(b.mode!=="SPEC_ONLY"||b.engineVersion!==INVENTORY_ENGINE_VERSION||
     Object.keys(b).some(k=>!["mode","engineVersion","specificationId"].includes(k)))fail(400,"INVALID_OFFLINE_ASSESSMENT_REQUEST");
  const key=req.headers["idempotency-key"];
  if(typeof key!=="string"||!/^[a-zA-Z0-9:_-]{8,128}$/.test(key))fail(400,"IDEMPOTENCY_KEY_REQUIRED");
  const t=tenant(req),newId=uuid();
  const result=await withTenant(t,async tx=>{
    const target=await tx.query("SELECT lifecycle FROM api_targets WHERE id=$1 FOR UPDATE",[targetId]);
    if(!target.rowCount)fail(404,"TARGET_NOT_FOUND");
    if(target.rows[0].lifecycle!=="ACTIVE")fail(409,"TARGET_NOT_ACTIVE");
    const v=await tx.query("SELECT i.version_number,i.raw_fingerprint,i.normalized_fingerprint,i.snapshot,s.fingerprint FROM api_spec_inventories i JOIN api_specifications s ON s.id=i.specification_id AND s.tenant_id=i.tenant_id WHERE i.target_id=$1 AND i.specification_id=$2",[targetId,specificationId]);
    if(!v.rowCount)fail(404,"INVENTORY_VERSION_NOT_FOUND");
    const meta=v.rows[0],snapshot=meta.snapshot as Inventory;
    if(snapshot.rawFingerprint!==meta.raw_fingerprint||snapshot.normalizedFingerprint!==meta.normalized_fingerprint||
       snapshot.rawFingerprint!==meta.fingerprint||snapshot.normalizationVersion!=="phase02-v1")fail(409,"INVENTORY_INTEGRITY_FAILURE");
    const created=await tx.query("INSERT INTO api_assessments(id,tenant_id,target_id,specification_id,status,mode,idempotency_key,engine_version,inventory_version,inventory_raw_fingerprint,inventory_fingerprint) VALUES($1,$2,$3,$4,'QUEUED','SPEC_ONLY',$5,$6,$7,$8,$9) ON CONFLICT(tenant_id,idempotency_key) DO UPDATE SET id=api_assessments.id RETURNING id,target_id,specification_id,engine_version,inventory_fingerprint,status,created_at",
      [newId,t,targetId,specificationId,key,INVENTORY_ENGINE_VERSION,meta.version_number,meta.raw_fingerprint,meta.normalized_fingerprint]);
    const row=created.rows[0];
    if(row.target_id!==targetId||row.specification_id!==specificationId||row.engine_version!==INVENTORY_ENGINE_VERSION||
       row.inventory_fingerprint!==meta.normalized_fingerprint)fail(409,"IDEMPOTENCY_CONFLICT");
    if(row.status==="QUEUED")await tx.query("SELECT public.api_enqueue_assessment($1)",[row.id]);
    return row;
  });
  reply.code(result.id===newId?201:200).send({id:result.id,targetId:result.target_id,specificationId:result.specification_id,
    engineVersion:result.engine_version,status:result.status,mode:"SPEC_ONLY",networkRequestsAuthorized:0});
 });
 app.get("/v3/targets/:id/assessments",async req=>{
  const targetId=part(req,"id"),p=page(req);
  return withTenant(tenant(req),async tx=>{
   if(!(await tx.query("SELECT 1 FROM api_targets WHERE id=$1",[targetId])).rowCount)fail(404,"TARGET_NOT_FOUND");
   return (await tx.query("SELECT id,specification_id AS \"specificationId\",inventory_version AS \"specificationVersion\",engine_version AS \"engineVersion\",status,created_at AS \"createdAt\",completed_at AS \"completedAt\",error_code AS \"errorCode\" FROM api_assessments WHERE target_id=$1 AND engine_version='inventory-v1' ORDER BY created_at DESC,id DESC LIMIT $2 OFFSET $3",[targetId,p.limit,p.offset])).rows;
  });
 });
 app.get("/v3/assessments/:id",async req=>{
  return withTenant(tenant(req),async tx=>{
   const r=await tx.query("SELECT id,target_id AS \"targetId\",specification_id AS \"specificationId\",inventory_version AS \"specificationVersion\",inventory_fingerprint AS \"inventoryFingerprint\",engine_version AS \"engineVersion\",mode,status,error_code AS \"errorCode\",created_at AS \"createdAt\",completed_at AS \"completedAt\" FROM api_assessments WHERE id=$1 AND engine_version='inventory-v1'",[part(req,"id")]);
   if(!r.rowCount)fail(404,"ASSESSMENT_NOT_FOUND");return r.rows[0];
  });
 });
 const report=async(req:FastifyRequest)=>{
  return withTenant(tenant(req),async tx=>{
   const r=await tx.query("SELECT r.projection FROM api_reports r JOIN api_assessments a ON a.id=r.assessment_id AND a.tenant_id=r.tenant_id WHERE a.id=$1 AND a.engine_version='inventory-v1' AND a.status='COMPLETED'",[part(req,"id")]);
   if(!r.rowCount)fail(404,"REPORT_NOT_READY_OR_NOT_FOUND");return r.rows[0].projection as Record<string,unknown>;
  });
 };
 app.get("/v3/assessments/:id/report",report);
 app.get("/v3/assessments/:id/coverage",async req=>{
  const projection=await report(req);return {assessmentId:projection.assessmentId,engineVersion:projection.engineVersion,coverage:projection.coverage,warnings:projection.warnings,limitations:projection.limitations};
 });
 app.get("/v3/assessments/:id/findings",async req=>{
  const assessmentId=part(req,"id"),p=page(req),query=req.query as Record<string,unknown>;
  const category=typeof query.category==="string"?query.category:null,impact=typeof query.impact==="string"?query.impact:null;
  const confidence=typeof query.confidence==="string"?query.confidence:null,ruleId=typeof query.ruleId==="string"?query.ruleId:null;
  const operationKey=typeof query.operationKey==="string"?query.operationKey:null;
  if(category&&(!/^[A-Z_]{1,32}$/.test(category)))fail(400,"INVALID_CATEGORY");
  if(impact&&!["INFORMATIONAL","LOW","MEDIUM","HIGH"].includes(impact))fail(400,"INVALID_IMPACT");
  if(confidence&&!["HIGH","MEDIUM","LOW"].includes(confidence))fail(400,"INVALID_CONFIDENCE");
  if(ruleId&&!/^API03_[A-Z0-9_]{2,80}$/.test(ruleId))fail(400,"INVALID_RULE_FILTER");
  if(operationKey&&(operationKey.length>512||/[\x00-\x1f]/.test(operationKey)))fail(400,"INVALID_OPERATION_FILTER");
  return withTenant(tenant(req),async tx=>{
   if(!(await tx.query("SELECT 1 FROM api_assessments WHERE id=$1 AND engine_version='inventory-v1'",[assessmentId])).rowCount)fail(404,"ASSESSMENT_NOT_FOUND");
   return (await tx.query('SELECT f.id,f.rule_id AS "ruleId",f.rule_version AS "ruleRevision",f.stable_fingerprint AS "fingerprint",f.correlation_key AS "correlationKey",f.operation_key AS "operationKey",f.category,f.severity AS impact,f.evidence_confidence AS confidence,f.potential_impact AS "potentialImpact",f.explanation,f.remediation,f.validation_level AS "validationLevel",f.review_required AS "reviewRequired",f.evidence_id AS "evidenceId",e.pointer,e.content_json AS evidence FROM api_findings f JOIN api_evidence e ON e.id=f.evidence_id AND e.tenant_id=f.tenant_id WHERE f.assessment_id=$1 AND ($2::text IS NULL OR f.category=$2) AND ($3::text IS NULL OR f.severity=$3) AND ($4::text IS NULL OR f.evidence_confidence=$4) AND ($5::text IS NULL OR f.rule_id=$5) AND ($6::text IS NULL OR f.operation_key=$6) ORDER BY f.rule_id,f.operation_key,f.stable_fingerprint LIMIT $7 OFFSET $8',
    [assessmentId,category,impact,confidence,ruleId,operationKey,p.limit,p.offset])).rows;
  });
 });
 app.get("/v3/assessments/:id/findings/:findingId",async req=>{
  const assessmentId=part(req,"id"),findingId=part(req,"findingId");
  return withTenant(tenant(req),async tx=>{
   const r=await tx.query('SELECT f.id,f.rule_id AS "ruleId",f.rule_version AS "ruleRevision",f.stable_fingerprint AS fingerprint,f.correlation_key AS "correlationKey",f.operation_key AS "operationKey",f.category,f.severity AS impact,f.evidence_confidence AS confidence,f.potential_impact AS "potentialImpact",f.explanation,f.remediation,f.validation_level AS "validationLevel",f.review_required AS "reviewRequired",e.pointer,e.content_json AS evidence FROM api_findings f JOIN api_evidence e ON e.id=f.evidence_id AND e.tenant_id=f.tenant_id JOIN api_assessments a ON a.id=f.assessment_id AND a.tenant_id=f.tenant_id WHERE a.id=$1 AND a.engine_version=$3 AND f.id=$2',[assessmentId,findingId,INVENTORY_ENGINE_VERSION]);
   if(!r.rowCount)fail(404,"FINDING_NOT_FOUND");return r.rows[0];
  });
 });
 app.post("/v3/targets/:id/assessments/compare",async req=>{
  const targetId=part(req,"id"),b=body(req.body),from=id(b.fromAssessmentId),to=id(b.toAssessmentId);
  if(from===to)fail(400,"SAME_ASSESSMENT");
  return withTenant(tenant(req),async tx=>{
   const r=await tx.query("SELECT a.id,r.projection FROM api_assessments a JOIN api_reports r ON r.assessment_id=a.id AND r.tenant_id=a.tenant_id WHERE a.target_id=$1 AND a.id IN($2,$3) AND a.engine_version='inventory-v1' AND a.status='COMPLETED'",[targetId,from,to]);
   if(r.rowCount!==2)fail(404,"COMPLETED_ASSESSMENT_NOT_FOUND");
   const a=r.rows.find(row=>row.id===from)?.projection as DetectionResult;
   const z=r.rows.find(row=>row.id===to)?.projection as DetectionResult;
   const comparison=compareDetection(a,z);
   return {...comparison,fromAssessmentId:from,toAssessmentId:to,
    counts:{newlyObserved:comparison.newlyObserved.length,noLongerObserved:comparison.noLongerObserved.length,stillObserved:comparison.stillObserved.length,changed:comparison.changed.length},
    newlyObserved:comparison.newlyObserved.slice(0,100),noLongerObserved:comparison.noLongerObserved.slice(0,100),stillObserved:comparison.stillObserved.slice(0,100),changed:comparison.changed.slice(0,100),truncated:comparison.newlyObserved.length>100||comparison.noLongerObserved.length>100||comparison.stillObserved.length>100||comparison.changed.length>100};
  });
 });
 app.post("/v3/assessments/:id/cancel",async req=>{
  const assessmentId=part(req,"id");
  return withTenant(tenant(req),async tx=>{
   if(!(await tx.query("SELECT 1 FROM api_assessments WHERE id=$1 AND engine_version='inventory-v1'",[assessmentId])).rowCount)fail(404,"ASSESSMENT_NOT_FOUND");
   const r=await tx.query("SELECT public.api_cancel_assessment($1) AS cancelled",[assessmentId]);
   if(!r.rows[0].cancelled)fail(409,"NOT_CANCELLABLE");
   return {id:assessmentId,status:"CANCELLED"};
  });
 });
}
