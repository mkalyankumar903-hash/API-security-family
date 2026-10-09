/** Phase08 additive customer projections over accepted Phase05-07 authorities.
 * No new queue, scanning primitive, finding promotion, or Host authorization. */
import type {FastifyInstance,FastifyRequest} from "fastify";
import {withTenant} from "../../database/src/index.js";
import {RULES,planRules} from "../../pt/src/detection.js";
import {DETECTION_FIXTURE,isProfile} from "../../pt/src/security-fixture.js";
import {PtError} from "./pt.js";

const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
function id(x:unknown):string{
 if(typeof x!=="string"||!UUID.test(x))throw new PtError(400,"INVALID_ID");
 return x;
}
function opts(req:FastifyRequest,allowed:readonly string[]):Record<string,string>{
 const query=req.query as Record<string,unknown>;
 if(!query||typeof query!=="object"||Array.isArray(query))return {};
 if(Object.keys(query).some(k=>!allowed.includes(k)))throw new PtError(400,"UNSUPPORTED_PT_FILTER");
 const out:Record<string,string>={};
 for(const [k,v] of Object.entries(query)){
  if(typeof v!=="string"||v.length>120)throw new PtError(400,"INVALID_PT_FILTER");
  out[k]=v;
 }
 return out;
}
function pagination(q:Record<string,string>):{limit:number;offset:number}{
 const limit=q.limit===undefined?20:Number(q.limit),offset=q.offset===undefined?0:Number(q.offset);
 if(!Number.isInteger(limit)||limit<1||limit>100||!Number.isSafeInteger(offset)||offset<0||offset>10000)
  throw new PtError(400,"INVALID_PT_PAGINATION");
 return {limit,offset};
}
function date(s:string):string{
 if(!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z$/.test(s)||Number.isNaN(Date.parse(s)))
  throw new PtError(400,"INVALID_PT_DATE");
 return new Date(s).toISOString();
}
function ruleFilter(input:Record<string,string>):string[]{
 let filtered=[...RULES];
 if(input.ruleId){
  if(!RULES.some(x=>x.id===input.ruleId))throw new PtError(400,"UNKNOWN_DETECTION_RULE");
  filtered=filtered.filter(x=>x.id===input.ruleId);
 }
 if(input.category)filtered=filtered.filter(x=>x.category===input.category);
 if(input.impact)filtered=filtered.filter(x=>x.impact===input.impact);
 if(input.operationPath)filtered=filtered.filter(x=>x.path===input.operationPath);
 return filtered.map(x=>x.id);
}
function dbWhere():{parts:string[];values:unknown[];add:(condition:string,value:unknown)=>void}{
 const parts:string[]=[],values:unknown[]=[];
 return {parts,values,add(condition,value){values.push(value);parts.push(condition.replaceAll("?", "$"+values.length));}};
}
export function registerPtProductRoutes(app:FastifyInstance,identity:(req:FastifyRequest)=>string):void{
 app.get("/v8/pt/product",async()=>({
  productVersion:"isolated-synthetic-api-pt-v1",assessmentType:"SYNTHETIC_PT_FIXTURE",
  engineVersion:"pt-detection-v1",fixture:DETECTION_FIXTURE,fixtureVersion:1,
  supportedRules:RULES.map(r=>({id:r.id,revision:r.revision,category:r.category,
   impact:r.impact,path:r.path,evaluations:r.cases.length})),
  authorization:"SEPARATE_SIGNED_TEST_AUTHORITY",productionHost:"BLOCKED",customerNetworkRequests:0,
  runtimeCustomerVerification:false,canonicalFindingAuthority:false,verifiedFixedAuthority:false,
  assessmentStates:["QUEUED","PROCESSING","COMPLETED","FAILED","CANCELLED"],
  terminalCoverage:"pt-terminal-coverage-v1",actualHostIntegration:"NOT_FROZEN"
 }));
 app.post("/v8/pt/specifications/:id/plan-preview",async req=>{
  const specId=id((req.params as {id:unknown}).id),tenant=identity(req);
  const input=req.body;
  if(!input||typeof input!=="object"||Array.isArray(input))throw new PtError(400,"INVALID_BODY");
  const b=input as Record<string,unknown>;
  if(Object.keys(b).some(k=>!["ruleIds","profile","exclusions"].includes(k)))throw new PtError(400,"UNKNOWN_FIELD");
  if(!isProfile(b.profile))throw new PtError(400,"UNSUPPORTED_TRUSTED_PROFILE");
  if(!Array.isArray(b.ruleIds)||!b.ruleIds.length||b.ruleIds.length>8||b.ruleIds.some(x=>typeof x!=="string"))
   throw new PtError(400,"INVALID_DETECTION_RULE_SELECTION");
  let selection:ReturnType<typeof planRules>;
  try{selection=planRules(b.ruleIds as string[]);}
  catch{throw new PtError(400,"UNKNOWN_OR_DUPLICATE_RULE");}
  if(b.exclusions!==undefined&&(!Array.isArray(b.exclusions)||b.exclusions.length>20||
    b.exclusions.some(x=>typeof x!=="string"||x.length>255)))
   throw new PtError(400,"INVALID_EXCLUSIONS");
  const exclusions=b.exclusions as string[]|undefined??[];
  return withTenant(tenant,async tx=>{
   const spec=await tx.query("SELECT s.id,s.target_id,s.fingerprint FROM api_specifications s JOIN api_spec_inventories i ON i.specification_id=s.id AND i.tenant_id=s.tenant_id WHERE s.id=$1",[specId]);
   if(!spec.rowCount)throw new PtError(404,"SPECIFICATION_NOT_FOUND");
   const operations=await tx.query("SELECT operation_key,method,path FROM api_inventory_operations WHERE specification_id=$1 ORDER BY operation_key LIMIT 100",[specId]);
   const results=selection.map(rule=>{
    const op=operations.rows.find(x=>x.method==="GET"&&x.path===rule.path);
    const applicable=Boolean(op)&&!exclusions.includes(rule.path);
    const reason=!op?"NO_SUPPORTED_GET_OPERATION":exclusions.includes(rule.path)?"OPERATION_EXCLUDED":"APPLICABLE";
    return {ruleId:rule.id,ruleRevision:rule.revision,requiredPath:rule.path,
     applicable,status:applicable?"APPLICABLE":reason==="OPERATION_EXCLUDED"?"SKIPPED":"BLOCKED",
     reason,evaluations:rule.cases.length,operationKey:applicable?op.operation_key:null};
   });
   return {version:"pt-plan-preview-v1",specificationId:specId,rawProfile:b.profile,
    specFingerprint:spec.rows[0].fingerprint,
    selectedRules:results.length,plannedEvaluations:results.reduce((n,x)=>n+x.evaluations,0),
    applicableEvaluations:results.filter(x=>x.applicable).reduce((n,x)=>n+x.evaluations,0),
    executable:results.every(x=>x.applicable),
    rules:results,productionHostAuthorization:"BLOCKED",customerNetworkRequests:0};
  });
 });
 app.get("/v8/pt/jobs/:id/progress",async req=>{
  const jid=id((req.params as {id:unknown}).id),tenant=identity(req);
  return withTenant(tenant,async tx=>{
   const r=await tx.query("SELECT a.status,a.error_code,p.rules,p.evaluations FROM api_pt_detection_plans p JOIN api_assessments a ON a.id=p.assessment_id AND a.tenant_id=p.tenant_id WHERE p.assessment_id=$1",[jid]);
   if(!r.rowCount)throw new PtError(404,"DETECTION_JOB_NOT_FOUND");
   const tally=await tx.query("SELECT state,count(*)::int AS n FROM api_pt_detection_evaluations WHERE assessment_id=$1 GROUP BY state",[jid]);
   const counts=Object.fromEntries(tally.rows.map(x=>[x.state,x.n])) as Record<string,number>;
   const planned=(r.rows[0].evaluations as unknown[]).length;
   const consumed=counts.CONSUMED??0,uncertain=counts.UNCERTAIN??0,reserved=counts.RESERVED??0;
   return {version:"pt-progress-v1",assessmentId:jid,status:r.rows[0].status,errorCode:r.rows[0].error_code,
    requestedRules:(r.rows[0].rules as unknown[]).length,plannedEvaluations:planned,
    executedEvaluations:consumed,uncertainEvaluations:uncertain,inFlightReservations:reserved,
    notYetExecuted:Math.max(0,planned-consumed-uncertain-reserved),customerNetworkRequests:0,
    complete:r.rows[0].status==="COMPLETED",runtimeCustomerVerification:false};
  });
 });
 app.get("/v8/pt/findings",async req=>{
  const t=identity(req);
  const q=opts(req,["limit","offset","targetId","assessmentId","ruleId","category",
   "impact","confidence","status","operationKey","operationPath","fixtureProfile","search"]);
  const {limit,offset}=pagination(q);
  if(q.targetId)id(q.targetId);if(q.assessmentId)id(q.assessmentId);
  if(q.operationKey&&q.operationKey.length>120)throw new PtError(400,"INVALID_OPERATION_KEY");
  if(q.fixtureProfile&&!isProfile(q.fixtureProfile))throw new PtError(400,"INVALID_PROFILE");
  if(q.status&&q.status!=="OBSERVED")throw new PtError(400,"INVALID_OBSERVATION_STATUS");
  if(q.confidence&&!["HIGH","NONE"].includes(q.confidence))throw new PtError(400,"INVALID_CONFIDENCE");
  if(q.search&&q.search.length>80)throw new PtError(400,"INVALID_SEARCH");
  const ids=ruleFilter(q);
  if(q.confidence==="NONE"||ids.length===0)return {items:[],limit,offset,hasMore:false};
  return withTenant(t,async tx=>{
   const w=dbWhere();
   w.parts.push("a.status='COMPLETED'","d.status='OBSERVED'");
   w.add("d.rule_id = ANY(?::text[])",ids);
   if(q.targetId)w.add("j.target_id=?",q.targetId);
   if(q.assessmentId)w.add("a.id=?",q.assessmentId);
   if(q.fixtureProfile)w.add("p.fixture_profile=?",q.fixtureProfile);
   if(q.search)w.add("(position(lower(?) in lower(d.rule_id))>0 OR position(lower(?) in lower(d.code))>0)",q.search);
   if(q.operationKey)w.add("EXISTS (SELECT 1 FROM jsonb_array_elements(p.evaluations) e WHERE e->>'ruleId'=d.rule_id AND e->>'operationKey'=?)",q.operationKey);
   const limitArg=w.values.push(limit+1),offsetArg=w.values.push(offset);
   const list=await tx.query(`SELECT d.id,d.assessment_id,d.rule_id,d.rule_revision,d.code,d.fingerprint,
    j.target_id,a.specification_id,a.created_at,p.fixture_profile,p.fixture_version,
    s.spec_fingerprint
    FROM api_pt_detection_results d
    JOIN api_pt_detection_plans p ON p.assessment_id=d.assessment_id AND p.tenant_id=d.tenant_id
    JOIN api_pt_jobs j ON j.assessment_id=d.assessment_id AND j.tenant_id=d.tenant_id
    JOIN api_assessments a ON a.id=d.assessment_id AND a.tenant_id=d.tenant_id
    JOIN api_pt_scopes s ON s.id=j.scope_id AND s.tenant_id=j.tenant_id
    WHERE ${w.parts.join(" AND ")}
    ORDER BY a.created_at DESC,d.rule_id,d.id LIMIT $${limitArg} OFFSET $${offsetArg}`,w.values);
   const rows=list.rows.slice(0,limit).map(x=>{
    const rule=RULES.find(r=>r.id===x.rule_id)!;
    return {...x,category:rule.category,impact:rule.impact,confidence:"HIGH",
     validationLevel:"SYNTHETIC_PT_OBSERVATION",confirmedCustomerVulnerability:false,
     runtimeCustomerVerification:false,verifiedFixed:false};
   });
   return {items:rows,limit,offset,hasMore:list.rows.length>limit};
  });
 });
 app.get("/v8/pt/findings/:id",async req=>{
  const finding=id((req.params as {id:unknown}).id),tenant=identity(req);
  return withTenant(tenant,async tx=>{
   const q=await tx.query(`SELECT d.id,d.assessment_id,d.rule_id,d.rule_revision,d.code,
    d.fingerprint,d.evidence,j.target_id,a.specification_id,p.fixture_profile,
    p.fixture_version,s.spec_fingerprint,s.id AS scope_id
    FROM api_pt_detection_results d
    JOIN api_pt_detection_plans p ON p.assessment_id=d.assessment_id AND p.tenant_id=d.tenant_id
    JOIN api_pt_jobs j ON j.assessment_id=d.assessment_id AND j.tenant_id=d.tenant_id
    JOIN api_assessments a ON a.id=d.assessment_id AND a.tenant_id=d.tenant_id
    JOIN api_pt_scopes s ON s.id=j.scope_id AND s.tenant_id=j.tenant_id
    WHERE d.id=$1 AND a.status='COMPLETED' AND d.status='OBSERVED'`,[finding]);
   if(!q.rowCount)throw new PtError(404,"PT_FINDING_NOT_FOUND");
   const row=q.rows[0],rule=RULES.find(x=>x.id===row.rule_id);
   if(!rule||rule.revision!==row.rule_revision)throw new PtError(409,"HISTORICAL_RULE_REVISION_UNAVAILABLE");
   return {...row,category:rule.category,description:rule.description,
    expectedPolicy:rule.description,impact:rule.impact,confidence:"HIGH",
    remediation:rule.remediation,operationPath:rule.path,method:"GET",
    validationLevel:"SYNTHETIC_PT_OBSERVATION",confirmedCustomerVulnerability:false,
    runtimeCustomerVerification:false,verifiedFixed:false,customerNetworkRequests:0,
    limitation:"Repository-owned fixture evidence only; no real customer API tested"};
  });
 });
 app.get("/v8/pt/history",async req=>{
  const t=identity(req);
  const q=opts(req,["limit","offset","targetId","specificationId","status","engine",
   "fixtureProfile","ruleId","from","to"]);
  const {limit,offset}=pagination(q);
  if(q.targetId)id(q.targetId);if(q.specificationId)id(q.specificationId);
  if(q.status&&!["QUEUED","PROCESSING","COMPLETED","FAILED","CANCELLED"].includes(q.status))throw new PtError(400,"INVALID_STATUS");
  if(q.engine&&q.engine!=="pt-detection-v1")throw new PtError(400,"UNSUPPORTED_ENGINE");
  if(q.ruleId&&!RULES.some(x=>x.id===q.ruleId))throw new PtError(400,"UNKNOWN_DETECTION_RULE");
  if(q.fixtureProfile&&!isProfile(q.fixtureProfile))throw new PtError(400,"INVALID_PROFILE");
  return withTenant(t,async tx=>{
   const w=dbWhere();
   if(q.targetId)w.add("j.target_id=?",q.targetId);
   if(q.specificationId)w.add("a.specification_id=?",q.specificationId);
   if(q.status)w.add("a.status=?",q.status);
   if(q.fixtureProfile)w.add("p.fixture_profile=?",q.fixtureProfile);
   if(q.ruleId)w.add("p.rules @> ?::jsonb",JSON.stringify([{id:q.ruleId}]));
   if(q.from)w.add("a.created_at>=?::timestamptz",date(q.from));
   if(q.to)w.add("a.created_at<=?::timestamptz",date(q.to));
   const lim=w.values.push(limit+1),off=w.values.push(offset);
   const rows=await tx.query(`SELECT a.id,a.status,a.error_code,a.created_at,a.completed_at,
    a.specification_id,j.target_id,p.fixture_profile,p.fixture_version,p.engine_version,
    p.rules,p.plan_fingerprint,s.spec_fingerprint
    FROM api_pt_detection_plans p JOIN api_assessments a
    ON a.id=p.assessment_id AND a.tenant_id=p.tenant_id
    JOIN api_pt_jobs j ON j.assessment_id=p.assessment_id AND j.tenant_id=p.tenant_id
    JOIN api_pt_scopes s ON s.id=j.scope_id AND s.tenant_id=j.tenant_id
    WHERE ${w.parts.length?w.parts.join(" AND "):"TRUE"}
    ORDER BY a.created_at DESC,a.id DESC LIMIT $${lim} OFFSET $${off}`,w.values);
   return {items:rows.rows.slice(0,limit),limit,offset,hasMore:rows.rows.length>limit};
  });
 });
}
