/** Phase11 API Family composite product. The only executable runtime authority is
 * the accepted Phase06 governor via the existing Phase09 PT child. */
import type {FastifyInstance,FastifyRequest} from "fastify";
import type {PoolClient} from "pg";
import {withTenant,uuid} from "../../database/src/index.js";
import {PtError} from "./pt.js";
import {context,makePlan,checkPermit,stopped} from "./orchestrator.js";
import {planFingerprint} from "../../pt/src/detection.js";
import {DETECTION_FIXTURE} from "../../pt/src/security-fixture.js";
import {AUTONOMOUS_VAPT_ENGINE,buildAutonomousVaptPlan,autonomousVaptFingerprint,
 type VaptInput,type VaptPlan} from "../../pt/src/autonomous-vapt.js";
import type {OrchestrationPlan} from "../../pt/src/orchestrator.js";

const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const asId=(x:unknown)=>{if(typeof x!=="string"||!UUID.test(x))throw new PtError(400,"INVALID_ID");return x;};
const routeId=(req:FastifyRequest,name="id")=>asId((req.params as Record<string,unknown>)[name]);
const requestKey=(r:FastifyRequest)=>{
 const k=r.headers["idempotency-key"];
 if(typeof k!=="string"||!/^[a-zA-Z0-9:_-]{8,128}$/.test(k))throw new PtError(400,"IDEMPOTENCY_KEY_REQUIRED");
 return k;
};
const positive=(x:unknown,d=30,max=50)=>{const n=x===undefined?d:Number(x);
 if(!Number.isSafeInteger(n)||n<1||n>max)throw new PtError(400,"INVALID_LIMIT");return n;};
type OfflineRequest={mode:"OFFLINE_ONLY";targetId:string;specificationId:string};
type GovernedRequest={mode:"GOVERNED_SYNTHETIC";scopeId:string;policyId:string;profile:string};
type Request=OfflineRequest|GovernedRequest;
function input(value:unknown):Request{
 if(!value||typeof value!=="object"||Array.isArray(value))throw new PtError(400,"INVALID_VAPT_REQUEST");
 const b=value as Record<string,unknown>;
 if(b.mode==="OFFLINE_ONLY"){
  if(Object.keys(b).some(k=>!["mode","targetId","specificationId"].includes(k)))
   throw new PtError(400,"UNSUPPORTED_VAPT_FIELD");
  return {mode:"OFFLINE_ONLY",targetId:asId(b.targetId),specificationId:asId(b.specificationId)};
 }
 if(b.mode==="GOVERNED_SYNTHETIC"){
  if(Object.keys(b).some(k=>!["mode","scopeId","policyId","profile"].includes(k))||
   typeof b.policyId!=="string"||typeof b.profile!=="string"||
   b.policyId.length>96||b.profile.length>96)
   throw new PtError(400,"INVALID_GOVERNED_VAPT_REQUEST");
  return {mode:"GOVERNED_SYNTHETIC",scopeId:asId(b.scopeId),
   policyId:b.policyId,profile:b.profile};
 }
 throw new PtError(400,"UNSUPPORTED_VAPT_MODE");
}
type TargetRow={id:string;lifecycle:string;environment:string;verification_version:number;scope_revision:number};
type InventoryRow={version_number:number;raw_fingerprint:string;normalized_fingerprint:string;snapshot:{
 normalizedFingerprint:string;rawFingerprint:string;operations:unknown[]};original_format:string};
async function resolveInventory(tx:PoolClient,targetId:string,specId:string){
 const target=await tx.query("SELECT id,lifecycle,environment,verification_version,scope_revision FROM api_targets WHERE id=$1 FOR UPDATE",[targetId]);
 const t=target.rows[0] as TargetRow|undefined;
 if(!t)throw new PtError(404,"TARGET_NOT_FOUND");
 if(t.lifecycle!=="ACTIVE")throw new PtError(409,"TARGET_NOT_ACTIVE");
 const s=await tx.query("SELECT i.version_number,i.raw_fingerprint,i.normalized_fingerprint,i.snapshot,i.original_format FROM api_spec_inventories i WHERE i.target_id=$1 AND i.specification_id=$2",[targetId,specId]);
 const inv=s.rows[0] as InventoryRow|undefined;
 if(!inv)throw new PtError(409,"IMMUTABLE_SPECIFICATION_INVENTORY_REQUIRED");
 if(inv.snapshot?.normalizedFingerprint!==inv.normalized_fingerprint||
  inv.snapshot?.rawFingerprint!==inv.raw_fingerprint)
  throw new PtError(409,"INVENTORY_FINGERPRINT_MISMATCH");
 const operations=await tx.query("SELECT operation_key AS key,method,path,auth_state AS \"authState\" FROM api_inventory_operations WHERE specification_id=$1 ORDER BY operation_key LIMIT 5001",[specId]);
 const rich=await tx.query("SELECT 1 FROM api_rich_inventories WHERE specification_id=$1",[specId]);
 return {t,inv,operations:operations.rows as VaptInput["operations"],offlineEngine:rich.rowCount?"inventory-v2" as const:"inventory-v1" as const};
}
async function create(tx:PoolClient,tenant:string,b:Request,key:string,lineage:string|null){
 // Transaction-scoped tenant+key admission lock prevents read-before-insert races.
 // A replay returns the committed same workflow and never creates a second child.
 await tx.query("SELECT pg_advisory_xact_lock(hashtext($1),hashtext($2))",[tenant,key]);
 // Idempotency is a historical identity lookup, never an instruction to replay
 // authorized runtime interactions or refresh an expired permit.
 const old=await tx.query("SELECT v.parent_assessment_id,v.plan,v.mode FROM api_assessments a JOIN api_vapt11_assessments v ON v.parent_assessment_id=a.id WHERE a.idempotency_key=$1",[key]);
 if(old.rowCount){
  const p=old.rows[0].plan as VaptPlan;
  const same=old.rows[0].mode===b.mode&&(b.mode==="OFFLINE_ONLY"?
   p.targetId===b.targetId&&p.specificationId===b.specificationId:
   p.scopeId===b.scopeId&&p.ptPolicyId===b.policyId&&p.ptProfile===b.profile);
  if(!same)throw new PtError(409,"IDEMPOTENCY_CONFLICT");
  return {id:old.rows[0].parent_assessment_id,created:false,planFingerprint:autonomousVaptFingerprint(p)};
 }
 let targetId:string,specId:string,pt:OrchestrationPlan|null=null;
 if(b.mode==="GOVERNED_SYNTHETIC"){
  // Exact Phase09 authority validation: stop -> target -> signed permit.
  if(await stopped(tx,tenant,true))throw new PtError(409,"EMERGENCY_STOP_ACTIVE");
  const {s,current,permit:p,operations}=await context(tx,b.scopeId,true);
  const denied=checkPermit(tenant,s,current,p);
  if(denied)throw new PtError(409,denied);
  if(!p)throw new PtError(409,"AUTHORIZATION_MISSING");
  pt=makePlan(b.policyId,b.profile,tenant,s,p,operations);
  if(pt.maxEvaluations>p.claims.maxEvaluations-p.consumed-p.reserved)
   throw new PtError(409,"PERMIT_BUDGET_EXHAUSTED");
  const active=await tx.query("SELECT count(*)::int AS tenant_active,count(*) FILTER(WHERE j.target_id=$1)::int AS target_active,count(*) FILTER(WHERE j.permit_id=$2)::int AS permit_active FROM api_pt_jobs j JOIN api_assessments a ON a.id=j.assessment_id WHERE j.tenant_id=$3 AND a.status IN('QUEUED','PROCESSING')",[s.target_id,p.id,tenant]);
  if(active.rows[0].tenant_active>=3||active.rows[0].target_active>=2||
   active.rows[0].permit_active>=s.max_concurrency)throw new PtError(409,"CONCURRENCY_LIMIT");
  targetId=s.target_id;specId=s.specification_id;
 }else {targetId=b.targetId;specId=b.specificationId;}
 const {t,inv,operations,offlineEngine}=await resolveInventory(tx,targetId,specId);
 if(pt&&(t.environment!=="SYNTHETIC"||
  pt.binding.specFingerprint!==inv.raw_fingerprint||
  pt.binding.specificationVersion!==inv.version_number))
  throw new PtError(409,"PT_SPECIFICATION_CONTEXT_CHANGED");
 const requested:VaptInput={tenantId:tenant,targetId,specificationId:specId,
  specificationVersion:inv.version_number,specFingerprint:inv.raw_fingerprint,
  inventoryFingerprint:inv.normalized_fingerprint,
  targetVerificationVersion:t.verification_version,targetScopeRevision:t.scope_revision,
  offlineEngine,operations,mode:b.mode,ptPlan:pt};
 const plan=buildAutonomousVaptPlan(requested),fingerprint=autonomousVaptFingerprint(plan);
 const parent=uuid(),offline=uuid(),ptChild=pt?uuid():null;
 const assessments=[
  [parent,b.mode==="OFFLINE_ONLY"?"SPEC_ONLY":"SYNTHETIC_PT_FIXTURE",AUTONOMOUS_VAPT_ENGINE,key],
  [offline,"SPEC_ONLY",offlineEngine,"vapt11-offline-"+parent],
  ...(ptChild?[[ptChild,"SYNTHETIC_PT_FIXTURE","pt-orchestrator-v1","vapt11-pt-"+parent]]:[])
 ];
 for(const [aid,mode,engine,idem] of assessments){
  await tx.query("INSERT INTO api_assessments(id,tenant_id,target_id,specification_id,status,mode,idempotency_key,engine_version,inventory_version,inventory_raw_fingerprint,inventory_fingerprint) VALUES($1,$2,$3,$4,'QUEUED',$5,$6,$7,$8,$9,$10)",
   [aid,tenant,targetId,specId,mode,idem,engine,inv.version_number,inv.raw_fingerprint,inv.normalized_fingerprint]);
 }
 if(pt&&ptChild){
  await tx.query("INSERT INTO api_pt_jobs(assessment_id,tenant_id,target_id,scope_id,permit_id,operation_keys,job_deadline) VALUES($1,$2,$3,$4,$5,$6::jsonb,now()+($7::text||' milliseconds')::interval)",
   [ptChild,tenant,targetId,pt.binding.scopeId,pt.binding.permitId,
    JSON.stringify([...new Set(pt.evaluations.map(x=>x.operationKey))]),pt.binding.deadlineMs]);
  const detection={engineVersion:"pt-detection-v1",fixtureVersion:1,fixtureId:DETECTION_FIXTURE,
   profile:pt.profile,rules:pt.rules,evaluations:pt.evaluations,
   specFingerprint:pt.binding.specFingerprint,scopeId:pt.binding.scopeId};
  await tx.query("INSERT INTO api_pt_detection_plans(assessment_id,tenant_id,fixture_version,fixture_profile,engine_version,rules,evaluations,plan_fingerprint) VALUES($1,$2,1,$3,'pt-detection-v1',$4::jsonb,$5::jsonb,$6)",
   [ptChild,tenant,pt.profile,JSON.stringify(pt.rules),JSON.stringify(pt.evaluations),planFingerprint(detection)]);
  const fp=planFingerprint(pt);
  await tx.query("INSERT INTO api_pt9_plans(assessment_id,tenant_id,policy_id,policy_version,plan,fingerprint) VALUES($1,$2,$3,$4,$5::jsonb,$6)",
   [ptChild,tenant,pt.policyId,pt.policyVersion,JSON.stringify(pt),fp]);
  for(const [n,s] of pt.stages.entries())await tx.query(
   "INSERT INTO api_pt9_stages(id,tenant_id,assessment_id,stage_id,stage_type,ordinal,dependencies,evaluation_keys,planned) VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,$8::jsonb,$9)",
   [uuid(),tenant,ptChild,s.id,s.type,n,JSON.stringify(s.dependencies),JSON.stringify(s.evaluationKeys),s.budget]);
 }
 await tx.query("INSERT INTO api_vapt11_assessments(parent_assessment_id,tenant_id,target_id,specification_id,offline_assessment_id,pt_assessment_id,mode,plan,fingerprint,lineage_parent_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,$10)",
  [parent,tenant,targetId,specId,offline,ptChild,b.mode,JSON.stringify(plan),fingerprint,lineage]);
 await tx.query("INSERT INTO api_vapt11_events(id,tenant_id,parent_assessment_id,code,details) VALUES($1,$2,$3,'PARENT_ADMITTED',$4::jsonb)",
  [uuid(),tenant,parent,JSON.stringify({offlineAssessmentId:offline,ptAssessmentId:ptChild,fingerprint})]);
 // No PT or parent is enqueued yet; migration 015 wakes the next dependency
 // transactionally after each authoritative child terminal transition.
 await tx.query("SELECT public.api_enqueue_assessment($1)",[offline]);
 return {id:parent,created:true,status:"QUEUED",planFingerprint:fingerprint,
  offlineAssessmentId:offline,ptAssessmentId:ptChild,syntheticOnly:true,customerNetworkRequests:0};
}
export function registerAutonomousVaptRoutes(app:FastifyInstance,identity:(r:FastifyRequest)=>string):void{
 app.get("/v11/api-vapt/capabilities",async()=>({
  engineVersion:AUTONOMOUS_VAPT_ENGINE,product:"ISOLATED SYNTHETIC AUTONOMOUS API VAPT",
  permittedModes:["OFFLINE_ONLY","GOVERNED_SYNTHETIC"],realHostAuthorization:"UNAVAILABLE",
  customerNetworkRequests:0,verifiedFixed:false,
  notice:"NOT AUTHORIZED FOR LIVE CUSTOMER API TESTING"}));
 app.get("/v11/api-vapt/scopes/:id/preview",async req=>{
  const tenant=identity(req),sid=routeId(req),q=req.query as Record<string,unknown>;
  if(Object.keys(q).some(k=>!["policyId","profile"].includes(k))||
   typeof q.policyId!=="string"||typeof q.profile!=="string")throw new PtError(400,"INVALID_PREVIEW_QUERY");
  return withTenant(tenant,async tx=>{
   const {s,current,permit:p,operations}=await context(tx,sid);
   const pt=makePlan(q.policyId as string,q.profile as string,tenant,s,p,operations);
   const {t,inv,operations:all,offlineEngine}=await resolveInventory(tx,s.target_id,s.specification_id);
   const plan=buildAutonomousVaptPlan({tenantId:tenant,targetId:s.target_id,
    specificationId:s.specification_id,specificationVersion:inv.version_number,
    specFingerprint:inv.raw_fingerprint,inventoryFingerprint:inv.normalized_fingerprint,
    targetVerificationVersion:t.verification_version,targetScopeRevision:t.scope_revision,
    offlineEngine,mode:"GOVERNED_SYNTHETIC",operations:all,ptPlan:pt});
   const denied=await stopped(tx,tenant)?"EMERGENCY_STOP_ACTIVE":checkPermit(tenant,s,current,p);
   return {plan,planFingerprint:autonomousVaptFingerprint(plan),
    authorizationReady:denied===null,denialCode:denied,
    executable:denied===null&&!!p&&pt.maxEvaluations<=p.claims.maxEvaluations-p.consumed-p.reserved,
    remainingPermitEvaluations:p?p.claims.maxEvaluations-p.consumed-p.reserved:0,
    limitation:"SYNTHETIC FIXTURE RESULTS DO NOT CONFIRM CUSTOMER VULNERABILITIES"};
  });
 });
 app.post("/v11/api-vapt/assessments",async(req,reply)=>{
  const b=input(req.body),key=requestKey(req),tenant=identity(req);
  const result=await withTenant(tenant,tx=>create(tx,tenant,b,key,null));
  reply.code(result.created?201:200).send(result);
 });
 app.get("/v11/api-vapt/assessments/:id",async req=>{
  const t=identity(req),id=routeId(req);
  return withTenant(t,async tx=>{
   const r=await tx.query("SELECT v.plan,v.fingerprint,v.mode,v.offline_assessment_id,v.pt_assessment_id,v.lineage_parent_id,a.id,a.status,a.error_code,a.created_at,a.completed_at FROM api_vapt11_assessments v JOIN api_assessments a ON a.id=v.parent_assessment_id AND a.tenant_id=v.tenant_id WHERE v.parent_assessment_id=$1",[id]);
   if(!r.rowCount)throw new PtError(404,"VAPT_ASSESSMENT_NOT_FOUND");
   const row=r.rows[0];
   const children=await tx.query("SELECT id,engine_version,status,error_code,created_at,completed_at FROM api_assessments WHERE id=ANY($1::uuid[]) ORDER BY created_at,id",[[row.offline_assessment_id,...(row.pt_assessment_id?[row.pt_assessment_id]:[])]]);
   return {...row,children:children.rows,customerNetworkRequests:0,customerRuntimeVerified:false,verifiedFixed:false};
  });
 });
 app.get("/v11/api-vapt/assessments/:id/findings",async req=>{
  const t=identity(req),id=routeId(req),q=req.query as Record<string,unknown>;
  const allowed=["source","ruleId","category","impact","confidence","limit","offset"];
  if(Object.keys(q).some(k=>!allowed.includes(k)))throw new PtError(400,"INVALID_FINDINGS_FILTER");
  const limit=positive(q.limit,30,50),offset=q.offset===undefined?0:Number(q.offset);
  if(!Number.isSafeInteger(offset)||offset<0||offset>100000)throw new PtError(400,"INVALID_OFFSET");
  for(const key of ["source","ruleId","category","impact","confidence"]){
   if(q[key]!==undefined&&(typeof q[key]!=="string"||(q[key] as string).length>96))
    throw new PtError(400,"INVALID_FINDINGS_FILTER");
  }
  return withTenant(t,async tx=>(await tx.query(
   "SELECT stable_key,source,projection,created_at FROM api_vapt11_correlations WHERE parent_assessment_id=$1 AND ($2::text IS NULL OR source=$2) AND ($3::text IS NULL OR projection->>'ruleId'=$3) AND ($4::text IS NULL OR projection->>'category'=$4) AND ($5::text IS NULL OR projection->>'impact'=$5) AND ($6::text IS NULL OR projection->>'confidence'=$6) ORDER BY created_at,stable_key LIMIT $7 OFFSET $8",
   [id,q.source??null,q.ruleId??null,q.category??null,q.impact??null,q.confidence??null,limit,offset])).rows);
 });
 app.get("/v11/api-vapt/assessments/:id/report",async req=>{
  const t=identity(req),id=routeId(req);
  return withTenant(t,async tx=>{
   const r=await tx.query("SELECT projection FROM api_vapt11_reports WHERE parent_assessment_id=$1",[id]);
   if(!r.rowCount)throw new PtError(409,"SUCCESSFUL_VAPT_REPORT_NOT_READY");
   return r.rows[0].projection;
  });
 });
 app.get("/v11/api-vapt/assessments/:id/terminal",async req=>{
  const t=identity(req),id=routeId(req);
  return withTenant(t,async tx=>{
   const r=await tx.query("SELECT projection FROM api_vapt11_terminal WHERE parent_assessment_id=$1",[id]);
   if(!r.rowCount)throw new PtError(409,"TERMINAL_DIAGNOSTIC_NOT_READY");
   return r.rows[0].projection;
  });
 });
 app.get("/v11/api-vapt/assessments/:id/export",async(req,reply)=>{
  const t=identity(req),id=routeId(req);
  const r=await withTenant(t,async tx=>tx.query("SELECT projection FROM api_vapt11_reports WHERE parent_assessment_id=$1",[id]));
  if(!r.rowCount)throw new PtError(409,"SUCCESSFUL_VAPT_REPORT_NOT_READY");
  reply.header("content-disposition","attachment; filename=isolated-api-vapt-"+id+".json")
   .type("application/json").send(r.rows[0].projection);
 });
 app.get("/v11/api-vapt/targets/:id/history",async req=>{
  const t=identity(req),id=routeId(req),q=req.query as Record<string,unknown>;
  if(Object.keys(q).some(k=>!["limit","status","mode"].includes(k)))throw new PtError(400,"INVALID_HISTORY_FILTER");
  const limit=positive(q.limit);
  if(q.status!==undefined&&!["QUEUED","PROCESSING","COMPLETED","FAILED","CANCELLED"].includes(String(q.status)))
   throw new PtError(400,"INVALID_STATUS_FILTER");
  if(q.mode!==undefined&&!["OFFLINE_ONLY","GOVERNED_SYNTHETIC"].includes(String(q.mode)))
   throw new PtError(400,"INVALID_MODE_FILTER");
  return withTenant(t,async tx=>(await tx.query(
   "SELECT v.parent_assessment_id AS id,v.mode,v.fingerprint,v.lineage_parent_id,a.status,a.error_code,a.created_at,a.completed_at FROM api_vapt11_assessments v JOIN api_assessments a ON a.id=v.parent_assessment_id AND a.tenant_id=v.tenant_id WHERE v.target_id=$1 AND ($2::text IS NULL OR a.status=$2) AND ($3::text IS NULL OR v.mode=$3) ORDER BY a.created_at DESC,a.id LIMIT $4",
   [id,q.status??null,q.mode??null,limit])).rows);
 });
 app.get("/v11/api-vapt/assessments/:id/compare/:otherId",async req=>{
  const t=identity(req),first=routeId(req),second=routeId(req,"otherId");
  if(first===second)throw new PtError(409,"IDENTICAL_ASSESSMENT_COMPARISON");
  return withTenant(t,async tx=>{
   const r=await tx.query("SELECT v.parent_assessment_id,v.plan,p.projection FROM api_vapt11_assessments v JOIN api_vapt11_reports p ON p.parent_assessment_id=v.parent_assessment_id AND p.tenant_id=v.tenant_id WHERE v.parent_assessment_id=ANY($1::uuid[])",[[first,second]]);
   if(r.rowCount!==2)throw new PtError(409,"COMPARISON_REQUIRES_SUCCESSFUL_REPORTS");
   const a=r.rows.find(x=>x.parent_assessment_id===first),b=r.rows.find(x=>x.parent_assessment_id===second);
   const x=a.plan as VaptPlan,y=b.plan as VaptPlan;
   if(x.targetId!==y.targetId||x.specFingerprint!==y.specFingerprint||
    x.inventoryFingerprint!==y.inventoryFingerprint||x.mode!==y.mode||
    x.offlineEngine!==y.offlineEngine||x.ptPolicyId!==y.ptPolicyId||
    x.ptPolicyVersion!==y.ptPolicyVersion||x.ptProfile!==y.ptProfile||
    x.fixtureId!==y.fixtureId||x.fixtureVersion!==y.fixtureVersion||
    x.scopeId!==y.scopeId||x.plannedEvaluations!==y.plannedEvaluations||
    JSON.stringify(x.operations)!==JSON.stringify(y.operations)||
    JSON.stringify(x.rules)!==JSON.stringify(y.rules))
    return {compatibility:"INCOMPATIBLE",reason:"VERSION_OR_FIXTURE_CONTEXT_CHANGED",
     customerNetworkRequests:0,verifiedFixed:false};
   const old=new Map((a.projection.findings as {key:string;evidenceFingerprint:string}[]).map(z=>[z.key,z.evidenceFingerprint]));
   const newer=new Map((b.projection.findings as {key:string;evidenceFingerprint:string}[]).map(z=>[z.key,z.evidenceFingerprint]));
   return {compatibility:"COMPATIBLE",newlyObserved:[...newer.keys()].filter(k=>!old.has(k)),
    stillObserved:[...newer.keys()].filter(k=>old.has(k)),
    noLongerObserved:[...old.keys()].filter(k=>!newer.has(k)),
    evidenceChanged:[...newer.keys()].filter(k=>old.has(k)&&old.get(k)!==newer.get(k)),
    verifiedFixed:false,customerRuntimeVerified:false,customerNetworkRequests:0,
    limitation:"NO LONGER OBSERVED != VERIFIED_FIXED; synthetic results do not establish customer security"};
  });
 });
 app.post("/v11/api-vapt/assessments/:id/reassess",async(req,reply)=>{
  const tenant=identity(req),id=routeId(req),key=requestKey(req);
  const body=req.body??{};
  if(typeof body!=="object"||Array.isArray(body)||
   Object.keys(body).some(k=>k!=="scopeId"))
   throw new PtError(400,"INVALID_REASSESSMENT_BODY");
  const override=(body as {scopeId?:unknown}).scopeId;
  const newScopeId=override===undefined?null:asId(override);
  const result=await withTenant(tenant,async tx=>{
   const r=await tx.query("SELECT plan,mode FROM api_vapt11_assessments WHERE parent_assessment_id=$1",[id]);
   if(!r.rowCount)throw new PtError(404,"HISTORICAL_ASSESSMENT_NOT_FOUND");
   const p=r.rows[0].plan as VaptPlan;
   const offline=r.rows[0].mode==="OFFLINE_ONLY";
   if(offline&&newScopeId)throw new PtError(400,"OFFLINE_REASSESSMENT_HAS_NO_SCOPE");
   const chosen=newScopeId??p.scopeId;
   if(!offline){
    // Changed authority must be an independently signed scope on the SAME
    // historical target. Do not borrow a permit from another target or tenant.
    const candidate=await tx.query("SELECT target_id FROM api_pt_scopes WHERE id=$1",[asId(chosen)]);
    if(!candidate.rowCount||candidate.rows[0].target_id!==p.targetId)
     throw new PtError(409,"REASSESSMENT_SCOPE_TARGET_MISMATCH");
   }
   const b:Request=offline?
    {mode:"OFFLINE_ONLY",targetId:p.targetId,specificationId:p.specificationId}:
    {mode:"GOVERNED_SYNTHETIC",scopeId:asId(chosen),policyId:p.ptPolicyId!,profile:p.ptProfile!};
   return create(tx,tenant,b,key,id);
  });
  reply.code(result.created?201:200).send(result);
 });
 app.post("/v11/api-vapt/assessments/:id/cancel",async req=>{
  const tenant=identity(req),id=routeId(req);
  return withTenant(tenant,async tx=>{
   const r=await tx.query("SELECT offline_assessment_id,pt_assessment_id FROM api_vapt11_assessments WHERE parent_assessment_id=$1",[id]);
   if(!r.rowCount)throw new PtError(404,"VAPT_ASSESSMENT_NOT_FOUND");
   const parent=await tx.query("SELECT status FROM api_assessments WHERE id=$1 FOR UPDATE",[id]);
   if(!["QUEUED","PROCESSING"].includes(parent.rows[0]?.status))
    throw new PtError(409,"VAPT_NOT_CANCELLABLE");
   // Accepted assessment cancellation, never direct governor/queue mutation.
   await tx.query("SELECT public.api_cancel_assessment($1)",[id]);
   for(const child of [r.rows[0].offline_assessment_id,r.rows[0].pt_assessment_id]){
    if(child)await tx.query("SELECT public.api_cancel_assessment($1)",[child]);
   }
   const diagnostic={schemaVersion:"autonomous-api-vapt-terminal-v1",assessmentId:id,
    status:"CANCELLED",code:"CUSTOMER_CANCELLED",verifiedFixed:false,
    customerRuntimeVerified:false,limitation:"Completed evidence and consumed budgets are preserved"};
   await tx.query("INSERT INTO api_vapt11_terminal(id,tenant_id,parent_assessment_id,status,code,projection,fingerprint) VALUES($1,$2,$3,'CANCELLED','CUSTOMER_CANCELLED',$4::jsonb,$5) ON CONFLICT(tenant_id,parent_assessment_id) DO NOTHING",
    [uuid(),tenant,id,JSON.stringify(diagnostic),planFingerprint(diagnostic)]);
   await tx.query("INSERT INTO api_vapt11_events(id,tenant_id,parent_assessment_id,code) VALUES($1,$2,$3,'CUSTOMER_CANCELLED')",[uuid(),tenant,id]);
   return {id,status:"CANCELLED",verifiedFixed:false,customerNetworkRequests:0};
  });
 });
 app.get("/v11/api-vapt/assessments/:id/audit",async req=>{
  const tenant=identity(req),id=routeId(req);
  return withTenant(tenant,async tx=>(await tx.query("SELECT code,details,created_at FROM api_vapt11_events WHERE parent_assessment_id=$1 ORDER BY created_at,id LIMIT 100",[id])).rows);
 });
}
