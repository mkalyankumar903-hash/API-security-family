import type {FastifyInstance,FastifyRequest} from "fastify";
import {withTenant,uuid} from "../../database/src/index.js";
import {AUTH_ENGINE_VERSION,AUTH_PROFILE,SCHEMES,FIXTURES,IDENTITIES,FIXTURE_OPERATIONS,declaredSchemeCoverage,type Identity} from "../../assessment-engine/src/auth-fixture.js";
import type {Inventory} from "../../discovery/src/index.js";

export class AuthFixtureError extends Error {constructor(public statusCode:number,public code:string){super(code);}}
const fail=(status:number,code:string):never=>{throw new AuthFixtureError(status,code);};
const id=(v:unknown):string=>typeof v==="string"&&/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i.test(v)?v:fail(400,"INVALID_IDENTIFIER");
const body=(v:unknown):Record<string,unknown>=>v!==null&&typeof v==="object"&&!Array.isArray(v)?v as Record<string,unknown>:fail(400,"INVALID_BODY");
const prop=(req:FastifyRequest,key:string)=>id((req.params as Record<string,unknown>)[key]);
const page=(req:FastifyRequest)=>{
 const q=req.query as Record<string,unknown>,limit=q.limit===undefined?25:Number(q.limit),offset=q.offset===undefined?0:Number(q.offset);
 if(!Number.isInteger(limit)||limit<1||limit>100||!Number.isSafeInteger(offset)||offset<0||offset>1000000)fail(400,"INVALID_PAGINATION");
 return {limit,offset};
};
const approved=(v:unknown,allowed:readonly string[]):string=>typeof v==="string"&&allowed.includes(v)?v:fail(400,"INVALID_FIXTURE_SELECTION");
const revision=(v:unknown):number=>typeof v==="number"&&Number.isSafeInteger(v)&&v>=1?v:fail(400,"INVALID_PROFILE_REVISION");
const key=(v:unknown)=>typeof v==="string"&&/^credref:[a-zA-Z0-9_-]{4,128}$/.test(v)?v:fail(400,"INVALID_OPAQUE_CREDENTIAL_REFERENCE");
const strict=(b:Record<string,unknown>,keys:string[])=>{if(Object.keys(b).some(k=>!keys.includes(k)))fail(400,"UNKNOWN_FIELDS_REJECTED");};
const enabled=()=>{if(process.env.NODE_ENV==="production"||process.env.SYNTHETIC_AUTH_ENABLED!=="true")fail(503,"SYNTHETIC_FIXTURE_EXECUTION_DISABLED");};
const limitMessage="SYNTHETIC AUTHENTICATED ASSESSMENT — NOT REAL HOST AUTHORIZATION OR CUSTOMER RUNTIME VERIFICATION.";
type TargetRow={id:string;lifecycle:string;environment:string;revision:number;scope_revision:number};
async function eligibility(tx:import("pg").PoolClient,targetId:string):Promise<TargetRow>{
 const target=await tx.query("SELECT id,lifecycle,environment,revision,scope_revision FROM api_targets WHERE id=$1 FOR UPDATE",[targetId]);
 if(!target.rowCount)fail(404,"TARGET_NOT_FOUND");
 const t=target.rows[0] as TargetRow;
 if(t.lifecycle!=="ACTIVE")fail(409,"TARGET_NOT_ACTIVE");
 if(t.environment!=="SYNTHETIC")fail(403,"REAL_TARGET_FIXTURE_PROHIBITED");
 return t;
}
async function requireReference(tx:import("pg").PoolClient,targetId:string,reference:string){
 if(!(await tx.query("SELECT 1 FROM api_target_credentials WHERE target_id=$1 AND reference=$2 AND status='UNVERIFIED_REFERENCE'",[targetId,reference])).rowCount)
  fail(409,"OPAQUE_CREDENTIAL_REFERENCE_UNAVAILABLE");
}
const projection=(r:Record<string,unknown>)=>({
 id:r.id,targetId:r.target_id,specificationId:r.specification_id,revision:r.revision,fixtureVersion:r.fixture_version,
 scheme:r.scheme,identityKey:r.identity_key,role:r.role_name,credentialReference:r.credential_reference,
 environment:r.environment,status:r.status,validationStatus:r.validation_status,createdAt:r.created_at,
 updatedAt:r.updated_at,expiresAt:r.expires_at,rotatedAt:r.rotated_at,syntheticOnly:true,productionCredentialAccess:false
});
async function profileEvent(tx:import("pg").PoolClient,tenant:string,p:string,revisionNo:number,action:string){
 await tx.query("INSERT INTO api_auth_profile_events(id,tenant_id,profile_id,revision,action,summary) VALUES($1,$2,$3,$4,$5,'{}'::jsonb)",
  [uuid(),tenant,p,revisionNo,action]);
 await tx.query("INSERT INTO api_audit(id,tenant_id,action,subject_id) VALUES($1,$2,$3,$4)",[uuid(),tenant,"AUTH04_"+action,p]);
}
export async function registerAuthFixtureRoutes(app:FastifyInstance,tenant:(req:FastifyRequest)=>string):Promise<void>{
 app.get("/v4/auth/capabilities",async()=>({engineVersion:AUTH_ENGINE_VERSION,analysisProfile:AUTH_PROFILE,mode:"SPEC_ONLY",
  schemes:SCHEMES,fixtures:FIXTURES,identityKeys:Object.keys(IDENTITIES),fixtureOperations:FIXTURE_OPERATIONS,
  fixtureTransport:"IN_PROCESS_FASTIFY_INJECT",customerNetworkRequestsAuthorized:0,methods:[],
  enabled:process.env.NODE_ENV!=="production"&&process.env.SYNTHETIC_AUTH_ENABLED==="true",notice:limitMessage}));
 app.get("/v4/auth/fixtures",async()=>({fixtures:FIXTURES.map(id=>({id,version:"1",immutable:true,expectedPolicy:"auth-policy-v1",
  syntheticOnly:true,description:id==="secure-v1"?"Secure fixture with enforced role/resource checks":"Deliberately vulnerable fixture: user-b can read user-a synthetic record"})),identities:IDENTITIES,operations:FIXTURE_OPERATIONS,notice:limitMessage}));
 app.get("/v4/targets/:id/profiles",async req=>{
  const targetId=prop(req,"id"),p=page(req);
  return withTenant(tenant(req),async tx=>{
   if(!(await tx.query("SELECT 1 FROM api_targets WHERE id=$1",[targetId])).rowCount)fail(404,"TARGET_NOT_FOUND");
   const r=await tx.query("SELECT * FROM api_auth_profiles WHERE target_id=$1 ORDER BY created_at DESC,id DESC LIMIT $2 OFFSET $3",[targetId,p.limit,p.offset]);
   return r.rows.map(projection);
  });
 });
 app.post("/v4/targets/:id/profiles",async(req,reply)=>{
  enabled();const targetId=prop(req,"id"),b=body(req.body),t=tenant(req);
  strict(b,["specificationId","fixtureVersion","scheme","identityKey","credentialReference"]);
  const specificationId=id(b.specificationId),fixture=approved(b.fixtureVersion,FIXTURES),
   scheme=approved(b.scheme,SCHEMES),identity=approved(b.identityKey,Object.keys(IDENTITIES)) as Identity,reference=key(b.credentialReference);
  const p=await withTenant(t,async tx=>{
   const target=await eligibility(tx,targetId);
   const inventory=await tx.query("SELECT 1 FROM api_spec_inventories WHERE target_id=$1 AND specification_id=$2",[targetId,specificationId]);
   if(!inventory.rowCount)fail(404,"IMPORTED_SPECIFICATION_NOT_FOUND");
   await requireReference(tx,targetId,reference);
   const profileId=uuid(),r=await tx.query(
    "INSERT INTO api_auth_profiles(id,tenant_id,target_id,specification_id,fixture_version,scheme,identity_key,role_name,credential_reference,target_revision,scope_revision) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING *",
    [profileId,t,targetId,specificationId,fixture,scheme,identity,IDENTITIES[identity].role,reference,target.revision,target.scope_revision]);
   await profileEvent(tx,t,profileId,1,"PROFILE_CREATED");
   return projection(r.rows[0]);
  });
  reply.code(201).send({...p,notice:limitMessage});
 });
 app.patch("/v4/profiles/:id",async req=>{
  enabled();const profileId=prop(req,"id"),b=body(req.body),t=tenant(req);
  strict(b,["revision","fixtureVersion","scheme","identityKey","credentialReference"]);
  const rev=revision(b.revision);
  const r=await withTenant(t,async tx=>{
   const previous=(await tx.query("SELECT * FROM api_auth_profiles WHERE id=$1 FOR UPDATE",[profileId])).rows[0];
   if(!previous)fail(404,"PROFILE_NOT_FOUND");
   if(previous.status!=="ACTIVE")fail(409,"PROFILE_REVOKED");
   if(previous.revision!==rev)fail(409,"STALE_PROFILE_REVISION");
   const target=await eligibility(tx,previous.target_id);
   const fixture=approved(b.fixtureVersion??previous.fixture_version,FIXTURES);
   const scheme=approved(b.scheme??previous.scheme,SCHEMES);
   const identity=approved(b.identityKey??previous.identity_key,Object.keys(IDENTITIES)) as Identity;
   const reference=key(b.credentialReference??previous.credential_reference);
   await requireReference(tx,previous.target_id,reference);
   const next=await tx.query(
    "UPDATE api_auth_profiles SET revision=revision+1,fixture_version=$2,scheme=$3,identity_key=$4,role_name=$5,credential_reference=$6,target_revision=$7,scope_revision=$8,validation_status='PENDING',expires_at=now()+interval '1 hour',rotated_at=now(),updated_at=now() WHERE id=$1 RETURNING *",
    [profileId,fixture,scheme,identity,IDENTITIES[identity].role,reference,target.revision,target.scope_revision]);
   await profileEvent(tx,t,profileId,rev+1,"PROFILE_ROTATED");
   return next.rows[0];
  });
  return {...projection(r),notice:limitMessage};
 });
 app.post("/v4/profiles/:id/validate",async req=>{
  enabled();const profileId=prop(req,"id"),b=body(req.body),rev=revision(b.revision),t=tenant(req);
  strict(b,["revision"]);
  return withTenant(t,async tx=>{
   const p=(await tx.query("SELECT * FROM api_auth_profiles WHERE id=$1 FOR UPDATE",[profileId])).rows[0];
   if(!p)fail(404,"PROFILE_NOT_FOUND");
   if(p.revision!==rev)fail(409,"STALE_PROFILE_REVISION");
   const tar=(await tx.query("SELECT lifecycle,environment,revision,scope_revision FROM api_targets WHERE id=$1",[p.target_id])).rows[0];
   const credential=await tx.query("SELECT 1 FROM api_target_credentials WHERE target_id=$1 AND reference=$2",[p.target_id,p.credential_reference]);
   const spec=await tx.query("SELECT 1 FROM api_spec_inventories WHERE target_id=$1 AND specification_id=$2",[p.target_id,p.specification_id]);
   const reasons:string[]=[];
   if(p.status!=="ACTIVE")reasons.push("PROFILE_REVOKED");
   if(new Date(p.expires_at).getTime()<=Date.now())reasons.push("PROFILE_EXPIRED");
   if(!tar||tar.lifecycle!=="ACTIVE")reasons.push("TARGET_NOT_ACTIVE");
   if(tar?.environment!=="SYNTHETIC")reasons.push("CUSTOMER_RUNTIME_PROHIBITED");
   if(tar?.revision!==p.target_revision||tar?.scope_revision!==p.scope_revision)reasons.push("STALE_TARGET_OR_SCOPE");
   if(!credential.rowCount)reasons.push("OPAQUE_REFERENCE_UNAVAILABLE");
   if(!spec.rowCount)reasons.push("SPECIFICATION_UNAVAILABLE");
   await tx.query("UPDATE api_auth_profiles SET validation_status=$2,updated_at=now() WHERE id=$1",[profileId,reasons.length?"INVALID":"VALID"]);
   await profileEvent(tx,t,profileId,rev,reasons.length?"PROFILE_VALIDATION_DENIED":"PROFILE_VALIDATED");
   return {id:profileId,revision:rev,ready:reasons.length===0,reasons,
    actualCredentialRetrieved:false,syntheticCredentialIssuance:"ISOLATED_WORKER_ONLY",notice:limitMessage};
  });
 });
 app.post("/v4/profiles/:id/revoke",async req=>{
  const profileId=prop(req,"id"),b=body(req.body),rev=revision(b.revision),t=tenant(req);
  strict(b,["revision"]);
  return withTenant(t,async tx=>{
   const r=await tx.query("UPDATE api_auth_profiles SET status='REVOKED',validation_status='INVALID',revision=revision+1,updated_at=now() WHERE id=$1 AND revision=$2 AND status='ACTIVE' RETURNING *",[profileId,rev]);
   if(!r.rowCount)fail(409,"PROFILE_NOT_FOUND_OR_STALE");
   await profileEvent(tx,t,profileId,rev+1,"PROFILE_REVOKED");
   return {...projection(r.rows[0]),notice:limitMessage};
  });
 });
 app.get("/v4/profiles/:id/history",async req=>{
  const profileId=prop(req,"id"),p=page(req);
  return withTenant(tenant(req),async tx=>{
   if(!(await tx.query("SELECT 1 FROM api_auth_profiles WHERE id=$1",[profileId])).rowCount)fail(404,"PROFILE_NOT_FOUND");
   return (await tx.query('SELECT revision,action,summary,created_at AS "createdAt" FROM api_auth_profile_events WHERE profile_id=$1 ORDER BY created_at DESC,id DESC LIMIT $2 OFFSET $3',[profileId,p.limit,p.offset])).rows;
  });
 });
 app.post("/v4/targets/:id/assessments",async(req,reply)=>{
  enabled();const targetId=prop(req,"id"),b=body(req.body),t=tenant(req);
  strict(b,["specificationId","profileId","profileRevision","engineVersion","analysisProfile","mode"]);
  if(b.engineVersion!==AUTH_ENGINE_VERSION||b.analysisProfile!==AUTH_PROFILE||b.mode!=="SPEC_ONLY")
   fail(400,"ONLY_SYNTHETIC_SPEC_ONLY_ALLOWED");
  const specId=id(b.specificationId),profileId=id(b.profileId),rev=revision(b.profileRevision);
  const idem=req.headers["idempotency-key"];
  if(typeof idem!=="string"||!/^[a-zA-Z0-9:_-]{8,128}$/.test(idem))fail(400,"IDEMPOTENCY_KEY_REQUIRED");
  const newId=uuid();
  const r=await withTenant(t,async tx=>{
   const target=await eligibility(tx,targetId);
   const p=(await tx.query("SELECT * FROM api_auth_profiles WHERE id=$1 AND target_id=$2 AND specification_id=$3 FOR UPDATE",[profileId,targetId,specId])).rows[0];
   if(!p)fail(404,"PROFILE_NOT_FOUND");
   if(p.revision!==rev||p.validation_status!=="VALID"||p.status!=="ACTIVE"||
     p.target_revision!==target.revision||p.scope_revision!==target.scope_revision||
     new Date(p.expires_at).getTime()<=Date.now())fail(409,"PROFILE_VALIDATION_STALE_OR_EXPIRED");
   await requireReference(tx,targetId,p.credential_reference);
   const inv=(await tx.query("SELECT i.*,s.fingerprint FROM api_spec_inventories i JOIN api_specifications s ON s.id=i.specification_id AND s.tenant_id=i.tenant_id WHERE i.specification_id=$1 AND i.target_id=$2",[specId,targetId])).rows[0];
   if(!inv||inv.raw_fingerprint!==inv.fingerprint||inv.snapshot.normalizedFingerprint!==inv.normalized_fingerprint)fail(409,"IMMUTABLE_SPEC_INTEGRITY_FAILURE");
   const created=await tx.query(
    "INSERT INTO api_assessments(id,tenant_id,target_id,specification_id,status,mode,idempotency_key,engine_version,inventory_version,inventory_raw_fingerprint,inventory_fingerprint) VALUES($1,$2,$3,$4,'QUEUED','SPEC_ONLY',$5,$6,$7,$8,$9) ON CONFLICT(tenant_id,idempotency_key) DO UPDATE SET id=api_assessments.id RETURNING *",
    [newId,t,targetId,specId,idem,AUTH_ENGINE_VERSION,inv.version_number,inv.raw_fingerprint,inv.normalized_fingerprint]);
   const a=created.rows[0];
   if(a.engine_version!==AUTH_ENGINE_VERSION||a.target_id!==targetId||a.specification_id!==specId)fail(409,"IDEMPOTENCY_CONFLICT");
   if(a.id===newId){
    const declarations=declaredSchemeCoverage((inv.snapshot as Inventory).schemes);
    await tx.query("INSERT INTO api_auth_assessment_configs(assessment_id,tenant_id,profile_id,profile_revision,fixture_version,fixture_policy_version,declared_schemes,target_revision,scope_revision,specification_version) VALUES($1,$2,$3,$4,$5,'auth-policy-v1',$6::jsonb,$7,$8,$9)",
     [newId,t,profileId,p.revision,p.fixture_version,JSON.stringify(declarations),target.revision,target.scope_revision,inv.version_number]);
    await profileEvent(tx,t,profileId,rev,"ASSESSMENT_QUEUED");
   }else{
    const config=(await tx.query("SELECT profile_id,profile_revision FROM api_auth_assessment_configs WHERE assessment_id=$1",[a.id])).rows[0];
    if(!config||config.profile_id!==profileId||config.profile_revision!==rev)fail(409,"IDEMPOTENCY_CONFLICT");
   }
   if(a.status==="QUEUED")await tx.query("SELECT public.api_enqueue_assessment($1)",[a.id]);
   return {id:a.id,status:a.status,created:a.id===newId,fixtureVersion:p.fixture_version};
  });
  reply.code(r.created?201:200).send({id:r.id,status:r.status,fixtureVersion:r.fixtureVersion,mode:"SPEC_ONLY",engineVersion:AUTH_ENGINE_VERSION,
   analysisProfile:AUTH_PROFILE,customerNetworkRequestsAuthorized:0,notice:limitMessage});
 });
 app.get("/v4/targets/:id/assessments",async req=>{
  const tid=prop(req,"id"),p=page(req);
  return withTenant(tenant(req),async tx=>{
   if(!(await tx.query("SELECT 1 FROM api_targets WHERE id=$1",[tid])).rowCount)fail(404,"TARGET_NOT_FOUND");
   return (await tx.query("SELECT id,status,error_code AS \"errorCode\",specification_id AS \"specificationId\",created_at AS \"createdAt\" FROM api_assessments WHERE target_id=$1 AND engine_version='auth-fixture-v1' ORDER BY created_at DESC,id DESC LIMIT $2 OFFSET $3",[tid,p.limit,p.offset])).rows;
  });
 });
 const check=async(req:FastifyRequest,tx:import("pg").PoolClient)=>{
  const aid=prop(req,"id"),a=(await tx.query("SELECT a.id,a.status,a.error_code,a.target_id,a.specification_id,a.created_at,a.completed_at,c.profile_id,c.profile_revision,c.fixture_version FROM api_assessments a JOIN api_auth_assessment_configs c ON c.assessment_id=a.id AND c.tenant_id=a.tenant_id WHERE a.id=$1 AND a.engine_version='auth-fixture-v1'",[aid])).rows[0];
  if(!a)fail(404,"AUTH_ASSESSMENT_NOT_FOUND");return a;
 };
 app.get("/v4/assessments/:id",async req=>withTenant(tenant(req),async tx=>{
  const a=await check(req,tx);return {id:a.id,status:a.status,errorCode:a.error_code,profileId:a.profile_id,
   profileRevision:a.profile_revision,fixtureVersion:a.fixture_version,specificationId:a.specification_id,
   createdAt:a.created_at,completedAt:a.completed_at,notice:limitMessage};
 }));
 app.get("/v4/assessments/:id/evaluations",async req=>{
  const p=page(req);return withTenant(tenant(req),async tx=>{
   const a=await check(req,tx);
   return (await tx.query('SELECT id,rule_id AS "ruleId",identity_key AS identity,role_name AS role,operation_key AS "operationKey",expected,observed,http_status AS status,response_bytes AS "responseBytes",outcome AS result,fingerprint,fixture_only AS "fixtureOnly",reason FROM api_auth_evaluations WHERE assessment_id=$1 ORDER BY rule_id,id LIMIT $2 OFFSET $3',[a.id,p.limit,p.offset])).rows;
  });
 });
 app.get("/v4/assessments/:id/findings",async req=>{
  const p=page(req);return withTenant(tenant(req),async tx=>{
   const a=await check(req,tx);
   return (await tx.query('SELECT f.id,f.rule_id AS "ruleId",f.operation_key AS "operationKey",f.category,f.explanation,f.remediation,f.validation_level AS "validationLevel",f.stable_fingerprint AS fingerprint,e.id AS "evidenceId",e.content_json AS evidence FROM api_findings f JOIN api_evidence e ON e.id=f.evidence_id AND e.tenant_id=f.tenant_id WHERE f.assessment_id=$1 ORDER BY f.rule_id LIMIT $2 OFFSET $3',[a.id,p.limit,p.offset])).rows;
  });
 });
 app.get("/v4/assessments/:id/evidence/:evidenceId",async req=>{
  const evidenceId=prop(req,"evidenceId");
  return withTenant(tenant(req),async tx=>{
   const a=await check(req,tx),r=await tx.query("SELECT id,pointer,content_json FROM api_evidence WHERE id=$1 AND assessment_id=$2",[evidenceId,a.id]);
   if(!r.rowCount)fail(404,"EVIDENCE_NOT_FOUND");return r.rows[0];
  });
 });
 const report=async(req:FastifyRequest)=>withTenant(tenant(req),async tx=>{
  const a=await check(req,tx);
  if(a.status!=="COMPLETED")fail(404,"REPORT_NOT_READY_OR_NOT_FOUND");
  const r=await tx.query("SELECT projection FROM api_reports WHERE assessment_id=$1",[a.id]);
  if(!r.rowCount)fail(404,"REPORT_NOT_READY_OR_NOT_FOUND");return r.rows[0].projection as Record<string,unknown>;
 });
 app.get("/v4/assessments/:id/report",report);
 app.get("/v4/assessments/:id/coverage",async req=>{
  const r=await report(req);return {assessmentId:r.assessmentId,coverage:r.coverage,declaredSchemes:r.declaredSchemes,limitations:r.limitations,notice:limitMessage};
 });
 app.post("/v4/targets/:id/assessments/compare",async req=>{
  const tid=prop(req,"id"),b=body(req.body);strict(b,["fromAssessmentId","toAssessmentId"]);
  const from=id(b.fromAssessmentId),to=id(b.toAssessmentId);if(from===to)fail(400,"SAME_ASSESSMENT");
  return withTenant(tenant(req),async tx=>{
   const r=await tx.query("SELECT a.id,r.projection FROM api_assessments a JOIN api_reports r ON r.assessment_id=a.id AND r.tenant_id=a.tenant_id WHERE a.target_id=$1 AND a.id IN($2,$3) AND a.status='COMPLETED' AND a.engine_version='auth-fixture-v1'",[tid,from,to]);
   if(r.rowCount!==2)fail(404,"COMPLETED_ASSESSMENTS_NOT_FOUND");
   const a=r.rows.find(x=>x.id===from).projection,z=r.rows.find(x=>x.id===to).projection;
   const old=new Set((a.observations as {fingerprint:string}[]).map(x=>x.fingerprint));
   const now=new Set((z.observations as {fingerprint:string}[]).map(x=>x.fingerprint));
   return {fromAssessmentId:from,toAssessmentId:to,fixtureOnly:true,productionRuntimeComparison:false,
    newlyObserved:[...now].filter(x=>!old.has(x)),noLongerObserved:[...old].filter(x=>!now.has(x)),
    stillObserved:[...now].filter(x=>old.has(x)),notice:limitMessage};
  });
 });
 app.post("/v4/assessments/:id/cancel",async req=>withTenant(tenant(req),async tx=>{
  const a=await check(req,tx);
  const r=await tx.query("SELECT public.api_cancel_assessment($1) AS cancelled",[a.id]);
  if(!r.rows[0].cancelled)fail(409,"NOT_CANCELLABLE");
  return {id:a.id,status:"CANCELLED",notice:limitMessage};
 }));
}
