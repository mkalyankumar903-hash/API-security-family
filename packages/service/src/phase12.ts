/** Phase12 presentation facade: no execution, queue, governor or permit imports. */
import type {FastifyInstance,FastifyRequest} from "fastify";
import {withTenant,uuid} from "../../database/src/index.js";
import {planFingerprint} from "../../pt/src/detection.js";
import {PtError} from "./pt.js";

const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const id=(v:unknown):string=>{if(typeof v!=="string"||!UUID.test(v))throw new PtError(400,"INVALID_ID");return v;};
const record=(v:unknown):Record<string,unknown>=>v!==null&&typeof v==="object"&&!Array.isArray(v)?v as Record<string,unknown>:{};
const num=(v:unknown):number=>typeof v==="number"&&Number.isSafeInteger(v)&&v>=0?v:0;
const text=(v:unknown,max=300):string=>{
 if(typeof v!=="string")return "";
 return [...v.slice(0,max)].map(ch=>ch.charCodeAt(0)<32||ch.charCodeAt(0)===127?" ":ch).join("")
 .replace(/Bearer\s+[^\s,;]+/gi,"Bearer [REDACTED]")
 .replace(/(api[_ -]?key|password|secret|access[_ -]?token)\s*[:=]\s*[^\s,;]+/gi,"$1=[REDACTED]");
};
const disclaimer="SYNTHETIC/DETERMINISTIC TEST EVIDENCE ONLY. No customer runtime vulnerability is confirmed. UNKNOWN IS NOT SAFE. No VERIFIED_FIXED authority.";
export type PresentationMetadata={id:string;assessmentId:string;fingerprint:string;createdAt:string};
export function presentVaptReport(value:unknown,meta:PresentationMetadata){
 const r=record(value);
 if(r.schemaVersion!=="autonomous-api-vapt-report-v1"||r.status!=="COMPLETED"||
    r.syntheticOnly!==true||r.customerRuntimeVerified!==false||r.verifiedFixed!==false||
    r.assessmentId!==meta.assessmentId||r.customerNetworkRequests!==0||
    !/^[a-f0-9]{64}$/.test(meta.fingerprint)||planFingerprint(r)!==meta.fingerprint)
   throw new PtError(409,"IMMUTABLE_SOURCE_REPORT_INTEGRITY_INVALID");
 const coverage=record(r.coverage);
 const all=Array.isArray(r.findings)?r.findings:[];
 if(all.length>1000)throw new PtError(413,"REPORT_PRESENTATION_LIMIT");
 const findings=all.map((item:unknown)=>{
   const f=record(item),priority=record(f.priority);
   return {key:text(f.key,70),source:text(f.source,30),ruleId:text(f.ruleId,96),
    category:text(f.category,50),impact:text(f.impact,50),confidence:text(f.confidence,50),
    operationKey:text(f.operationKey,512),explanation:text(f.explanation,1000),
    remediation:text(f.remediation,1000),evidenceFingerprint:text(f.evidenceFingerprint,70),
    correlation:text(f.correlation,80),priorityReason:text(priority.reason,300),
    customerRuntimeVerified:false,verifiedFixed:false};
 });
 const limitations=Array.isArray(r.limitations)?r.limitations.slice(0,100).map(x=>text(x,500)):[];
 const mode=r.mode==="GOVERNED_SYNTHETIC"?"GOVERNED_SYNTHETIC":"OFFLINE_ONLY";
 return {
  schemaVersion:"api-security-report-presentation-v1",
  reportId:meta.id,assessmentId:meta.assessmentId,sourceFingerprint:meta.fingerprint,
  sourceCreatedAt:meta.createdAt,mode,syntheticOnly:true,customerRuntimeVerified:false,
  verifiedFixed:false,customerNetworkRequests:0,disclaimer,
  scope:{targetId:id(r.targetId),specificationId:id(r.specificationId),
   specificationVersion:num(r.specificationVersion),engineVersion:text(r.engineVersion,60),
   specimenFingerprint:text(r.specFingerprint,64),fixtureVersion:r.fixtureVersion??null},
  summary:{findingCount:findings.length,offlineOnly:mode==="OFFLINE_ONLY",
   fullAuthorizedSyntheticAssessment:mode==="GOVERNED_SYNTHETIC"&&r.fullAuthorizedVaptCompleted===true},
  coverage:{importedOperations:num(coverage.importedOperations),
   offlineOperations:num(coverage.offlineOperations),ptRulesSelected:num(coverage.ptRulesSelected),
   ptRulesExecuted:num(coverage.ptRulesExecuted),ptEvaluationsPlanned:num(coverage.ptEvaluationsPlanned),
   ptEvaluationsExecuted:num(coverage.ptEvaluationsExecuted),
   notTested:coverage.ptNotTested===true},
  findings,limitations:[...limitations,disclaimer]
 };
}
const page=(q:Record<string,unknown>)=>{
 if(Object.keys(q).some(k=>!["targetId","status","limit","offset"].includes(k)))
  throw new PtError(400,"INVALID_FILTER");
 const limit=q.limit===undefined?30:Number(q.limit),offset=q.offset===undefined?0:Number(q.offset);
 if(!Number.isInteger(limit)||limit<1||limit>50||!Number.isSafeInteger(offset)||offset<0||offset>100000)
  throw new PtError(400,"INVALID_PAGINATION");
 if(q.status!==undefined&&typeof q.status!=="string")throw new PtError(400,"INVALID_FILTER");
 const status=q.status===undefined?null:q.status;
 if(status!==null&&!["QUEUED","PROCESSING","COMPLETED","FAILED","CANCELLED"].includes(status as string))
  throw new PtError(400,"INVALID_FILTER");
 return {limit,offset,status};
};
async function stored(tenant:string,reportId:string,action:"PRESENTATION_VIEWED"|"JSON_EXPORTED"){
 return withTenant(tenant,async tx=>{
  const r=await tx.query(
   "SELECT r.id,r.parent_assessment_id,r.fingerprint,r.created_at,r.projection "+
   "FROM public.api_vapt11_reports r WHERE r.parent_assessment_id=$1 LIMIT 1",[reportId]);
  if(!r.rowCount)throw new PtError(404,"REPORT_NOT_FOUND_OR_NOT_READY");
  const x=r.rows[0];
  const projection=presentVaptReport(x.projection,{id:x.id,assessmentId:x.parent_assessment_id,
   fingerprint:x.fingerprint,createdAt:x.created_at instanceof Date?x.created_at.toISOString():String(x.created_at)});
  if(Buffer.byteLength(JSON.stringify(projection),"utf8")>1024*1024)throw new PtError(413,"REPORT_PRESENTATION_LIMIT");
  await tx.query("INSERT INTO api_v12_report_audit(id,tenant_id,parent_assessment_id,action) VALUES($1,$2,$3,$4)",[uuid(),tenant,reportId,action]);
  return projection;
 });
}
export function registerPhase12Routes(app:FastifyInstance,identity:(req:FastifyRequest)=>string){
 app.get("/v12/capabilities",async()=>({schemaVersion:"phase12-capabilities-v1",
  ai:{mode:"DISABLED",configured:false,executionTools:0,externalModelInvoked:false},
  reports:{presentation:true,json:true,pdf:false,externalPublicSharing:false},
  context:"ISOLATED_SYNTHETIC_ONLY"}));
 app.get("/v12/overview",async req=>{
  const q=(req.query??{}) as Record<string,unknown>;
  if(Object.keys(q).some(k=>k!=="targetId"))throw new PtError(400,"INVALID_FILTER");
  const targetId=q.targetId===undefined?null:id(q.targetId);
  return withTenant(identity(req),async tx=>{
   if(targetId){
    const check=await tx.query("SELECT 1 FROM api_targets WHERE id=$1",[targetId]);
    if(!check.rowCount)throw new PtError(404,"TARGET_NOT_FOUND");
   }
   const targets=await tx.query("SELECT lifecycle,count(*)::int AS count FROM api_targets WHERE ($1::uuid IS NULL OR id=$1) GROUP BY lifecycle ORDER BY lifecycle",[targetId]);
   const specs=await tx.query("SELECT count(*)::int AS count FROM api_specifications WHERE ($1::uuid IS NULL OR target_id=$1)",[targetId]);
   const assessment=await tx.query("SELECT a.status,a.mode,a.engine_version,count(*)::int AS count FROM api_assessments a WHERE ($1::uuid IS NULL OR a.target_id=$1) GROUP BY a.status,a.mode,a.engine_version ORDER BY a.status,a.mode,a.engine_version",[targetId]);
   const reports=await tx.query("SELECT count(*)::int AS count FROM api_vapt11_reports r JOIN api_vapt11_assessments v ON v.parent_assessment_id=r.parent_assessment_id AND v.tenant_id=r.tenant_id WHERE ($1::uuid IS NULL OR v.target_id=$1)",[targetId]);
   return {schemaVersion:"phase12-overview-v1",targetId,targets:targets.rows,specificationCount:specs.rows[0].count,
    assessments:assessment.rows,immutableCompositeReports:reports.rows[0].count,
    notice:disclaimer};
  });
 });
 app.get("/v12/assessments",async req=>{
  const q=(req.query??{}) as Record<string,unknown>,p=page(q),targetId=id(q.targetId);
  return withTenant(identity(req),async tx=>{
   const target=await tx.query("SELECT 1 FROM api_targets WHERE id=$1",[targetId]);
   if(!target.rowCount)throw new PtError(404,"TARGET_NOT_FOUND");
   const result=await tx.query("SELECT a.id,a.target_id AS \"targetId\",a.specification_id AS \"specificationId\",a.status,a.mode,a.engine_version AS \"engineVersion\",a.error_code AS \"errorCode\",a.created_at AS \"createdAt\",a.completed_at AS \"completedAt\",v.parent_assessment_id IS NOT NULL AS \"isAutonomousVapt\",r.id AS \"reportId\" FROM api_assessments a LEFT JOIN api_vapt11_assessments v ON v.parent_assessment_id=a.id AND v.tenant_id=a.tenant_id LEFT JOIN api_vapt11_reports r ON r.parent_assessment_id=a.id AND r.tenant_id=a.tenant_id WHERE a.target_id=$1 AND ($2::text IS NULL OR a.status=$2) ORDER BY a.created_at DESC,a.id DESC LIMIT $3 OFFSET $4",
    [targetId,p.status,p.limit,p.offset]);
   return result.rows;
  });
 });
 app.get("/v12/reports/:id/presentation",async req=>{
  const reportId=id((req.params as Record<string,unknown>).id);
  return stored(identity(req),reportId,"PRESENTATION_VIEWED");
 });
 app.get("/v12/reports/:id/export.json",async(req,reply)=>{
  const reportId=id((req.params as Record<string,unknown>).id);
  const report=await stored(identity(req),reportId,"JSON_EXPORTED");
  const json=JSON.stringify({...report,export:{schemaVersion:"phase12-json-export-v1",sourceFingerprint:report.sourceFingerprint}});
  if(Buffer.byteLength(json,"utf8")>1024*1024)throw new PtError(413,"REPORT_EXPORT_LIMIT");
  reply.header("Cache-Control","no-store").header("X-Content-Type-Options","nosniff")
    .header("Content-Disposition",'attachment; filename="lumicsec-api-presentation-'+reportId+'.json"')
    .type("application/json; charset=utf-8").send(json);
 });
 app.get("/v12/ai/capabilities",async()=>({mode:"DISABLED",providerConfigured:false,externalModelInvoked:false,
  executionAuthority:false,explanationsAvailable:false,reason:"NO_APPROVED_AI_PROVIDER"}));
 app.post("/v12/ai/explain",async()=>{throw new PtError(503,"AI_DISABLED_NO_PROVIDER");});
}
