import type {FastifyInstance,FastifyRequest} from "fastify";
import {withTenant} from "../../database/src/index.js";
import {RULE_CATALOG} from "../../assessment-engine/src/inventory.js";

/** Read-only, tenant-scoped projection of existing assessment authorities.
 * Phase 05 does not introduce a queue, finding authority, scanner or Host substitute. */
export class UnifiedError extends Error {
  constructor(public statusCode:number,public code:string){super(code);}
}
const fail=(status:number,code:string):never=>{throw new UnifiedError(status,code);};
const uid=(x:unknown):string=>typeof x==="string"&&/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i.test(x)?x:fail(400,"INVALID_IDENTIFIER");
const param=(req:FastifyRequest,name:string)=>uid((req.params as Record<string,unknown>)[name]);
const query=(req:FastifyRequest)=>req.query as Record<string,unknown>;
const page=(q:Record<string,unknown>)=>{
  const limit=q.limit===undefined?25:Number(q.limit),offset=q.offset===undefined?0:Number(q.offset);
  if(!Number.isSafeInteger(limit)||limit<1||limit>100||!Number.isSafeInteger(offset)||offset<0||offset>1000000)
    fail(400,"INVALID_PAGINATION");
  return {limit,offset};
};
const optionalId=(x:unknown)=>x===undefined?null:uid(x);
const choice=(x:unknown,values:readonly string[]):string|null=>{
  if(x===undefined||x==="")return null;
  return typeof x==="string"&&values.includes(x)?x:fail(400,"INVALID_FILTER");
};
const term=(x:unknown,max=160):string=>{
  if(x===undefined)return "";
  if(typeof x!=="string"||x.length>max||/[^\x20-\x7e]/.test(x))fail(400,"INVALID_SEARCH");
  return x;
};
const date=(x:unknown):string|null=>{
  if(x===undefined)return null;
  if(typeof x!=="string"||! /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z$/.test(x)||!Number.isFinite(Date.parse(x)))
    fail(400,"INVALID_DATE");
  return x;
};
const engines=["legacy-v1","inventory-v1","auth-fixture-v1"] as const;
const states=["QUEUED","PROCESSING","COMPLETED","FAILED","CANCELLED"] as const;
const summarySql='SELECT a.id,a.target_id AS "targetId",t.name AS "targetName",t.environment,a.specification_id AS "specificationId",i.version_number AS "specificationVersion",s.format,a.inventory_fingerprint AS "inventoryFingerprint",a.engine_version AS "engineVersion",a.mode,a.status,a.error_code AS "errorCode",a.created_at AS "createdAt",a.completed_at AS "completedAt" FROM api_assessments a JOIN api_targets t ON t.id=a.target_id AND t.tenant_id=a.tenant_id JOIN api_specifications s ON s.id=a.specification_id AND s.tenant_id=a.tenant_id LEFT JOIN api_spec_inventories i ON i.specification_id=a.specification_id AND i.tenant_id=a.tenant_id';
const disclaimer="No runtime security validation. UNKNOWN != SAFE; NO EVIDENCE != SAFE; absence of an observation is NOT VERIFIED_FIXED.";
type Run={id:string;targetId:string;specificationId:string;engineVersion:string;status:string;specificationVersion:number|null};
type Fingerprint={fingerprint:string;correlationKey:string;ruleId:string;ruleVersion:string;operationKey:string|null;pointer:string};
export function comparePersistedFindings(from:Fingerprint[],to:Fingerprint[]) {
  const left=new Map(from.map(x=>[x.correlationKey,x])),right=new Map(to.map(x=>[x.correlationKey,x]));
  const newlyObserved=to.filter(x=>!left.has(x.correlationKey));
  const noLongerObserved=from.filter(x=>!right.has(x.correlationKey));
  const stillObserved=to.filter(x=>left.get(x.correlationKey)?.fingerprint===x.fingerprint);
  const evidenceChanged=to.filter(x=>left.has(x.correlationKey)&&left.get(x.correlationKey)?.fingerprint!==x.fingerprint);
  return {newlyObserved,noLongerObserved,stillObserved,evidenceChanged};
}
export async function registerUnifiedRoutes(app:FastifyInstance,tenant:(req:FastifyRequest)=>string):Promise<void>{
  app.get("/v5/engines",async()=>({
    revision:"phase05-engines-v1",mode:"SPEC_ONLY",maxRequests:0,methods:[],
    options:[
      {engineVersion:"inventory-v1",label:"Specification Security Assessment",input:"phase02-v1 immutable inventory",formats:["OPENAPI_3_0","OPENAPI_3_1","SWAGGER_2","POSTMAN_2_1"],rules:28,
        executedCatalogRules:RULE_CATALOG.filter(x=>!x.unsupported).length,notes:"Declaration-only; no runtime vulnerability confirmation."},
      {engineVersion:"auth-fixture-v1",label:"Synthetic Authentication & Authorization Validation",input:"Phase 02 inventory and validated synthetic fixture profile",formats:["OPENAPI_3_0","OPENAPI_3_1","SWAGGER_2","POSTMAN_2_1"],
        notes:"Only trusted in-process fixtures. Does not test customer authentication."},
      {engineVersion:"legacy-v1",label:"Historical OpenAPI Specification Assessment",input:"Legacy compatible specification",formats:["OPENAPI_3_1","SWAGGER_2"],
        notes:"Preserved for historical compatibility; prefer inventory-v1 for new imports."}
    ],disclaimer
  }));
  app.get("/v5/assessments",async req=>{
    const q=query(req),p=page(q),targetId=optionalId(q.targetId),specificationId=optionalId(q.specificationId);
    const engine=choice(q.engineVersion,engines),status=choice(q.status,states);
    const after=date(q.from),before=date(q.to),search=term(q.search,36);
    return withTenant(tenant(req),async tx=>{
      if(targetId&&!(await tx.query("SELECT 1 FROM api_targets WHERE id=$1",[targetId])).rowCount)fail(404,"TARGET_NOT_FOUND");
      return (await tx.query(summarySql+
        " WHERE ($1::uuid IS NULL OR a.target_id=$1) AND ($2::uuid IS NULL OR a.specification_id=$2)"+
        " AND ($3::text IS NULL OR a.engine_version=$3) AND ($4::text IS NULL OR a.status=$4)"+
        " AND ($5::timestamptz IS NULL OR a.created_at>=$5) AND ($6::timestamptz IS NULL OR a.created_at<=$6)"+
        " AND ($7='' OR a.id::text LIKE $7||'%') ORDER BY a.created_at DESC,a.id DESC LIMIT $8 OFFSET $9",
        [targetId,specificationId,engine,status,after,before,search,p.limit,p.offset])).rows;
    });
  });
  const getRun=async(tx:import("pg").PoolClient,id:string):Promise<Run>=>{
    const row=(await tx.query(summarySql+" WHERE a.id=$1",[id])).rows[0] as Run|undefined;
    if(!row)fail(404,"ASSESSMENT_NOT_FOUND");
    return row!;
  };
  app.get("/v5/assessments/:id",async req=>withTenant(tenant(req),async tx=>getRun(tx,param(req,"id"))));
  app.get("/v5/assessments/:id/findings",async req=>{
    const q=query(req),p=page(q),id=param(req,"id");
    const impact=choice(q.impact,["INFORMATIONAL","LOW","MEDIUM","HIGH","CRITICAL_CANDIDATE"]);
    const confidence=choice(q.confidence,["HIGH","MEDIUM","LOW"]);
    const category=term(q.category,50),rule=term(q.ruleId,100),operation=term(q.operationKey,512),search=term(q.search,100);
    return withTenant(tenant(req),async tx=>{
      await getRun(tx,id);
      return (await tx.query(
        'SELECT f.id,f.assessment_id AS "assessmentId",f.rule_id AS "ruleId",f.rule_version AS "ruleVersion",'+
        'f.stable_fingerprint AS fingerprint,f.correlation_key AS "correlationKey",f.operation_key AS "operationKey",'+
        'f.category,f.severity AS impact,f.evidence_confidence AS confidence,f.potential_impact AS "potentialImpact",'+
        'f.explanation,f.remediation,f.confidence AS "observationType",f.validation_level AS "validationLevel",'+
        'f.review_required AS "reviewRequired",f.evidence_id AS "evidenceId",e.pointer AS "sourcePointer",'+
        'f.created_at AS "createdAt" FROM api_findings f JOIN api_evidence e ON e.id=f.evidence_id AND e.tenant_id=f.tenant_id'+
        ' WHERE f.assessment_id=$1 AND ($2::text IS NULL OR f.severity=$2)'+
        ' AND ($3::text IS NULL OR f.evidence_confidence=$3)'+
        ' AND ($4=\'\' OR f.category=$4) AND ($5=\'\' OR f.rule_id=$5)'+
        ' AND ($6=\'\' OR f.operation_key=$6)'+
        ' AND ($7=\'\' OR strpos(lower(f.rule_id),lower($7))>0 OR strpos(lower(coalesce(f.operation_key,\'\')),lower($7))>0)'+
        ' ORDER BY f.rule_id,f.operation_key NULLS FIRST,f.id LIMIT $8 OFFSET $9',
        [id,impact,confidence,category,rule,operation,search,p.limit,p.offset])).rows;
    });
  });
  app.get("/v5/assessments/:id/findings/:findingId",async req=>withTenant(tenant(req),async tx=>{
    const id=param(req,"id"),findingId=param(req,"findingId"),run=await getRun(tx,id);
    const row=(await tx.query(
      'SELECT f.id,f.rule_id AS "ruleId",f.rule_version AS "ruleVersion",f.operation_key AS "operationKey",'+
      'f.stable_fingerprint AS fingerprint,f.correlation_key AS "correlationKey",f.category,f.severity AS impact,'+
      'f.evidence_confidence AS confidence,f.potential_impact AS "potentialImpact",f.explanation,f.remediation,'+
      'f.confidence AS "observationType",f.validation_level AS "validationLevel",f.review_required AS "reviewRequired",'+
      'e.pointer AS "sourcePointer",e.fingerprint AS "evidenceFingerprint",e.content_json AS evidence'+
      ' FROM api_findings f JOIN api_evidence e ON e.id=f.evidence_id AND e.tenant_id=f.tenant_id'+
      ' WHERE f.assessment_id=$1 AND f.id=$2',[id,findingId])).rows[0];
    if(!row)fail(404,"FINDING_NOT_FOUND");
    return {...row,engineVersion:run.engineVersion,specificationId:run.specificationId,notice:disclaimer};
  }));
  const report=async(tx:import("pg").PoolClient,id:string)=>{
    const run=await getRun(tx,id);
    if(run.status!=="COMPLETED")fail(409,"REPORT_NOT_READY");
    const row=(await tx.query(
      'SELECT r.projection,s.fingerprint AS "rawFingerprint",i.normalized_fingerprint AS "normalizedFingerprint"'+
      ' FROM api_reports r JOIN api_assessments a ON a.id=r.assessment_id AND a.tenant_id=r.tenant_id'+
      ' JOIN api_specifications s ON s.id=a.specification_id AND s.tenant_id=a.tenant_id'+
      ' LEFT JOIN api_spec_inventories i ON i.specification_id=a.specification_id AND i.tenant_id=a.tenant_id'+
      ' WHERE r.assessment_id=$1',[id])).rows[0];
    if(!row)fail(404,"REPORT_NOT_FOUND");
    const value={schemaVersion:"phase05-report-v1",assessment:run,
      provenance:{rawFingerprint:row.rawFingerprint,normalizedFingerprint:row.normalizedFingerprint,
        engineVersion:run.engineVersion,specificationVersion:run.specificationVersion,
        validationLevel:run.engineVersion==="auth-fixture-v1"?"SYNTHETIC_AUTH_FIXTURE":"SPEC_ONLY"},
      immutableReport:row.projection,notice:disclaimer,verifiedFixed:false};
    if(Buffer.byteLength(JSON.stringify(value),"utf8")>1024*1024)fail(413,"REPORT_EXPORT_LIMIT");
    return value;
  };
  app.get("/v5/assessments/:id/report",async req=>withTenant(tenant(req),tx=>report(tx,param(req,"id"))));
  app.get("/v5/assessments/:id/export",async(req,reply)=>{
    const id=param(req,"id"),value=await withTenant(tenant(req),tx=>report(tx,id));
    reply.header("Cache-Control","no-store").header("X-Content-Type-Options","nosniff")
      .header("Content-Disposition",'attachment; filename="lumicsec-api-'+id+'.json"')
      .type("application/json; charset=utf-8");
    return value;
  });
  app.get("/v5/assessments/:id/coverage",async req=>withTenant(tenant(req),async tx=>{
    const id=param(req,"id"),run=await getRun(tx,id);
    const rules=(await tx.query(
      'SELECT rule_id AS "ruleId",rule_version AS "ruleVersion",execution_status AS status,'+
      'skip_reason AS "skipReason",match_count AS "matchCount",coverage FROM api_rule_results'+
      ' WHERE assessment_id=$1 ORDER BY rule_id,id LIMIT 500',[id])).rows;
    const reportRow=(await tx.query("SELECT projection FROM api_reports WHERE assessment_id=$1",[id])).rows[0];
    const projection=reportRow?.projection as Record<string,unknown>|undefined;
    return {assessmentId:id,engineVersion:run.engineVersion,status:run.status,
      rules,coverage:projection?.coverage??null,limitations:projection?.limitations??[disclaimer],
      warnings:projection?.warnings??[],operationsEvaluated:projection?.operationsAssessed??null,
      syntheticFixtureOnly:run.engineVersion==="auth-fixture-v1",runtimeValidation:false,
      notice:disclaimer};
  }));
  app.post("/v5/assessments/compare",async req=>{
    const b=req.body;
    if(!b||typeof b!=="object"||Array.isArray(b)||Object.keys(b).sort().join(",")!=="fromAssessmentId,toAssessmentId")
      fail(400,"INVALID_COMPARISON_REQUEST");
    const r=b as Record<string,unknown>,fromId=uid(r.fromAssessmentId),toId=uid(r.toAssessmentId);
    if(fromId===toId)fail(400,"SAME_ASSESSMENT");
    return withTenant(tenant(req),async tx=>{
      const from=await getRun(tx,fromId),to=await getRun(tx,toId);
      if(from.targetId!==to.targetId)fail(409,"TARGET_MISMATCH");
      const incompatible=(reason:string)=>({comparable:false,reason,fromAssessmentId:fromId,toAssessmentId:toId,
        newlyObserved:[],noLongerObserved:[],stillObserved:[],evidenceChanged:[],notice:disclaimer});
      if(from.engineVersion!==to.engineVersion)return incompatible("ENGINE_VERSION_INCOMPATIBLE");
      if(from.status!=="COMPLETED"||to.status!=="COMPLETED")return incompatible("INCOMPLETE_ASSESSMENT");
      if(from.engineVersion==="legacy-v1")return incompatible("LEGACY_FINDINGS_LACK_STABLE_CORRELATION");
      const coverage=await tx.query(
        'SELECT assessment_id,rule_id,rule_version,coalesce(execution_status,\'EVALUATED\') AS status'+
        ' FROM api_rule_results WHERE assessment_id IN($1,$2) ORDER BY rule_id,rule_version,status',
        [fromId,toId]);
      const signature=(id:string)=>coverage.rows.filter(x=>x.assessment_id===id)
        .map(x=>x.rule_id+":"+x.rule_version+":"+x.status).sort().join("|");
      if(from.engineVersion==="inventory-v1"&&signature(fromId)!==signature(toId))
        return incompatible("RULE_VERSION_OR_COVERAGE_INCOMPATIBLE");
      // Fixture versions are intentionally not interpreted as real customer policy changes.
      const rows=await tx.query(
        'SELECT f.assessment_id,f.stable_fingerprint AS fingerprint,f.correlation_key AS "correlationKey",'+
        'f.rule_id AS "ruleId",f.rule_version AS "ruleVersion",f.operation_key AS "operationKey",'+
        'e.pointer FROM api_findings f JOIN api_evidence e ON e.id=f.evidence_id AND e.tenant_id=f.tenant_id'+
        ' WHERE f.assessment_id IN($1,$2) ORDER BY f.rule_id,f.id LIMIT 1001',[fromId,toId]);
      if(rows.rowCount===1001)return incompatible("COMPARISON_RESULT_LIMIT");
      const all=rows.rows as (Fingerprint&{assessment_id:string})[];
      if(all.some(x=>!x.fingerprint||!x.correlationKey||!x.ruleVersion))
        return incompatible("INSUFFICIENT_COMPARISON_EVIDENCE");
      const difference=comparePersistedFindings(all.filter(x=>x.assessment_id===fromId),all.filter(x=>x.assessment_id===toId));
      return {comparable:true,reason:null,fromAssessmentId:fromId,toAssessmentId:toId,
        engineVersion:from.engineVersion,specificationVersions:[from.specificationVersion,to.specificationVersion],
        ...difference,counts:Object.fromEntries(Object.entries(difference).map(([key,list])=>[key,list.length])),
        syntheticFixtureOnly:from.engineVersion==="auth-fixture-v1",notice:disclaimer};
    });
  });
}
