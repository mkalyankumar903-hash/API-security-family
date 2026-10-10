/** Phase 12 finding/coverage projections from accepted immutable PostgreSQL correlation authority.
 * No queue, permit, governor, scanner, worker, Host or AI mutation imports. */
import type {FastifyInstance,FastifyRequest} from "fastify";
import {withTenant} from "../../database/src/index.js";
import {PtError} from "./pt.js";
import {presentVaptReport} from "./phase12.js";
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const HEX=/^[a-f0-9]{64}$/;
const id=(value:unknown)=>{if(typeof value!=="string"||!UUID.test(value))throw new PtError(400,"INVALID_ID");return value;};
const txt=(value:unknown,max=800)=>{
 if(typeof value!=="string")return "";
 return [...value.slice(0,max)].map(ch=>ch.charCodeAt(0)<32||ch.charCodeAt(0)===127?" ":ch).join("")
 .replace(/Bearer\s+[^\s,;]+/gi,"Bearer [REDACTED]")
 .replace(/(api[_ -]?key|password|secret|access[_ -]?token)\s*[:=]\s*[^\s,;]+/gi,"$1=[REDACTED]")
 .replace(/\bAKIA[0-9A-Z]{16}\b/g,"[REDACTED_AWS_KEY]")
 .replace(/\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g,"[REDACTED_JWT]");
};
const str=(query:Record<string,unknown>,key:string,len=96)=>{
 const v=query[key];if(v===undefined)return null;
 if(typeof v!=="string"||!v.trim()||v.length>len)throw new PtError(400,"INVALID_FILTER_"+key);
 return v;
};
function filter(request:FastifyRequest){
 const q=(request.query??{}) as Record<string,unknown>;
 const permitted=["targetId","assessmentId","source","category","impact","confidence","ruleId",
  "correlation","annotationState","fromDate","toDate","limit","offset"];
 if(Object.keys(q).some(k=>!permitted.includes(k)))throw new PtError(400,"INVALID_FINDING_FILTER");
 const targetId=id(q.targetId),assessmentId=q.assessmentId===undefined?null:id(q.assessmentId);
 const limit=q.limit===undefined?30:Number(q.limit),offset=q.offset===undefined?0:Number(q.offset);
 if(!Number.isSafeInteger(limit)||limit<1||limit>50||!Number.isSafeInteger(offset)||
  offset<0||offset>100000)throw new PtError(400,"INVALID_PAGINATION");
 const sources=["SPEC_ONLY","SYNTHETIC_PT","RELATED_EVIDENCE"];
 const source=str(q,"source",32);
 if(source&&!sources.includes(source))throw new PtError(400,"INVALID_EVIDENCE_SOURCE");
 const annotationState=str(q,"annotationState",32);
 if(annotationState&&!["UNANNOTATED","NEEDS_REVIEW","INVESTIGATING","REMEDIATION_PLANNED",
   "FIX_CLAIMED","DEFERRED","ACCEPTED_FOR_REVIEW"].includes(annotationState))
  throw new PtError(400,"INVALID_ANNOTATION_FILTER");
 const fromDate=str(q,"fromDate",30),toDate=str(q,"toDate",30);
 for(const date of [fromDate,toDate]){
  if(date&&!/^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z)?$/.test(date))
   throw new PtError(400,"INVALID_DATE_FILTER");
  if(date&&(!Number.isFinite(Date.parse(date))))throw new PtError(400,"INVALID_DATE_FILTER");
 }
 if(fromDate&&toDate&&Date.parse(fromDate)>Date.parse(toDate))
  throw new PtError(400,"INVALID_DATE_RANGE");
 return {targetId,assessmentId,source,category:str(q,"category",60),
  impact:str(q,"impact",60),confidence:str(q,"confidence",60),
  ruleId:str(q,"ruleId",100),correlation:str(q,"correlation",96),
  annotationState,fromDate,toDate,limit,offset};
}
function finding(row:Record<string,unknown>){
 const p=(row.projection&&typeof row.projection==="object"&&!Array.isArray(row.projection))?
  row.projection as Record<string,unknown>:{};
 const severity=txt(p.impact,60),confidence=txt(p.confidence,60);
 return {stableKey:row.stable_key,assessmentId:row.parent_assessment_id,
  targetId:row.target_id,createdAt:row.created_at,
  source:txt(row.source,40),ruleId:txt(p.ruleId,100),ruleRevision:txt(p.revision,64),
  operationKey:txt(p.operationKey,512),category:txt(p.category,60),
  impact:severity,confidence,correlation:txt(p.correlation,96),
  evidenceFingerprint:txt(p.evidenceFingerprint,64),
  observation:txt(p.explanation,1200),remediation:txt(p.remediation,1200),
  annotationState:row.annotation_state??"UNANNOTATED",
  annotationVersion:row.annotation_version??0,
  syntheticOnly:true,customerRuntimeVerified:false,verifiedFixed:false};
}
export function registerPhase12FindingRoutes(app:FastifyInstance,identity:(req:FastifyRequest)=>string){
 app.get("/v12/findings",async req=>{
  const q=filter(req);
  return withTenant(identity(req),async tx=>{
   const target=await tx.query("SELECT id FROM api_targets WHERE id=$1",[q.targetId]);
   if(!target.rowCount)throw new PtError(404,"TARGET_NOT_FOUND");
   const sql=`SELECT c.parent_assessment_id,c.stable_key,c.source,c.projection,v.target_id,
     a.created_at,notes.state AS annotation_state,notes.version AS annotation_version
    FROM api_vapt11_correlations c
    JOIN api_vapt11_assessments v ON v.parent_assessment_id=c.parent_assessment_id AND v.tenant_id=c.tenant_id
    JOIN api_vapt11_reports r ON r.parent_assessment_id=c.parent_assessment_id AND r.tenant_id=c.tenant_id
    JOIN api_assessments a ON a.id=c.parent_assessment_id AND a.tenant_id=c.tenant_id
    LEFT JOIN LATERAL (
      SELECT ann.state,ann.version FROM api_v12_annotations ann
      WHERE ann.parent_assessment_id=c.parent_assessment_id AND ann.stable_key=c.stable_key
      ORDER BY ann.version DESC LIMIT 1
    ) notes ON true
    WHERE v.target_id=$1 AND ($2::uuid IS NULL OR c.parent_assessment_id=$2)
     AND ($3::text IS NULL OR c.source=$3)
     AND ($4::text IS NULL OR c.projection->>'category'=$4)
     AND ($5::text IS NULL OR c.projection->>'impact'=$5)
     AND ($6::text IS NULL OR c.projection->>'confidence'=$6)
     AND ($7::text IS NULL OR c.projection->>'ruleId'=$7)
     AND ($8::text IS NULL OR c.projection->>'correlation'=$8)
     AND ($9::text IS NULL OR coalesce(notes.state,'UNANNOTATED')=$9)
     AND ($10::timestamptz IS NULL OR a.created_at >= $10)
     AND ($11::timestamptz IS NULL OR a.created_at <= $11)
    ORDER BY a.created_at DESC,c.parent_assessment_id DESC,c.stable_key ASC
    LIMIT $12 OFFSET $13`;
   const rows=await tx.query(sql,[q.targetId,q.assessmentId,q.source,q.category,
    q.impact,q.confidence,q.ruleId,q.correlation,q.annotationState,
    q.fromDate,q.toDate,q.limit,q.offset]);
   return {schemaVersion:"phase12-finding-explorer-v1",targetId:q.targetId,
    limit:q.limit,offset:q.offset,items:rows.rows.map(finding),
    disclaimer:"Synthetic and specification findings do not confirm a customer vulnerability."};
  });
 });
 app.get("/v12/reports/:id/findings/:key",async req=>{
  const t=identity(req),p=req.params as Record<string,unknown>,rid=id(p.id),key=p.key;
  if(typeof key!=="string"||!HEX.test(key))throw new PtError(400,"INVALID_FINDING_KEY");
  return withTenant(t,async tx=>{
   const found=await tx.query(`SELECT c.parent_assessment_id,c.stable_key,c.source,c.projection,v.target_id,
     a.created_at,notes.state AS annotation_state,notes.version AS annotation_version
     FROM api_vapt11_correlations c
     JOIN api_vapt11_assessments v ON v.parent_assessment_id=c.parent_assessment_id AND v.tenant_id=c.tenant_id
     JOIN api_vapt11_reports r ON r.parent_assessment_id=c.parent_assessment_id AND r.tenant_id=c.tenant_id
     JOIN api_assessments a ON a.id=c.parent_assessment_id AND a.tenant_id=c.tenant_id
     LEFT JOIN LATERAL(SELECT ann.state,ann.version FROM api_v12_annotations ann
      WHERE ann.parent_assessment_id=c.parent_assessment_id AND ann.stable_key=c.stable_key
      ORDER BY ann.version DESC LIMIT 1) notes ON true
     WHERE c.parent_assessment_id=$1 AND c.stable_key=$2 LIMIT 1`,[rid,key]);
   if(!found.rowCount)throw new PtError(404,"FINDING_NOT_FOUND");
   return {...finding(found.rows[0]),immutableEvidence:true,
    validationAdvice:"Request an authorized reassessment; do not infer VERIFIED_FIXED."};
  });
 });
 app.get("/v12/reports/:id/evidence/:key",async req=>{
  const t=identity(req),p=req.params as Record<string,unknown>,rid=id(p.id),key=p.key;
  if(typeof key!=="string"||!HEX.test(key))throw new PtError(400,"INVALID_EVIDENCE_KEY");
  return withTenant(t,async tx=>{
   const found=await tx.query(`SELECT c.stable_key,c.source,c.projection,
    r.projection AS report_projection,r.fingerprint AS source_fingerprint
    FROM api_vapt11_correlations c
    JOIN api_vapt11_reports r ON r.parent_assessment_id=c.parent_assessment_id AND r.tenant_id=c.tenant_id
    WHERE c.parent_assessment_id=$1 AND c.stable_key=$2 LIMIT 1`,[rid,key]);
   if(!found.rowCount)throw new PtError(404,"EVIDENCE_NOT_FOUND");
   const x=found.rows[0],f=x.projection as Record<string,unknown>,
    report=x.report_projection as Record<string,unknown>;
   return {schemaVersion:"phase12-redacted-evidence-v1",assessmentId:rid,
    findingKey:key,source:txt(x.source,32),ruleId:txt(f.ruleId,100),
    ruleRevision:txt(f.revision,64),operationKey:txt(f.operationKey,512),
    observation:txt(f.explanation,1200),evidenceFingerprint:txt(f.evidenceFingerprint,64),
    sourceFingerprint:txt(x.source_fingerprint,64),specificationFingerprint:txt(report.specFingerprint,64),
    fixtureVersion:typeof report.fixtureVersion==="number"?report.fixtureVersion:null,
    syntheticOnly:true,governed:report.mode==="GOVERNED_SYNTHETIC",
    customerRuntimeVerified:false,verifiedFixed:false,
    limitations:["Redacted observation only; original confidential response bodies are not accessible.",
     "No customer runtime vulnerability is confirmed."]};
  });
 });
 app.get("/v12/reports/:id/coverage",async req=>{
  const rid=id((req.params as Record<string,unknown>).id);
  return withTenant(identity(req),async tx=>{
   const row=await tx.query("SELECT id,parent_assessment_id,projection,fingerprint,created_at FROM api_vapt11_reports WHERE parent_assessment_id=$1",[rid]);
   if(!row.rowCount)throw new PtError(404,"REPORT_NOT_FOUND_OR_NOT_READY");
   const r=row.rows[0];
   const p=presentVaptReport(r.projection,{id:r.id,assessmentId:rid,fingerprint:r.fingerprint,
    createdAt:new Date(r.created_at).toISOString()});
   return {schemaVersion:"phase12-coverage-v1",assessmentId:rid,mode:p.mode,
    offline:{numerator:p.coverage.offlineOperations,denominator:p.coverage.importedOperations},
    syntheticRules:{numerator:p.coverage.ptRulesExecuted,denominator:p.coverage.ptRulesSelected},
    syntheticEvaluations:{numerator:p.coverage.ptEvaluationsExecuted,denominator:p.coverage.ptEvaluationsPlanned},
    autonomousStages:{numerator:p.autonomous.completedStages,denominator:p.autonomous.requiredStages},
    notTested:p.coverage.notTested,unknownIsSafe:false,verifiedFixed:false,
    limitations:p.limitations};
  });
 });
}
