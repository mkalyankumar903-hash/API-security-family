import type {FastifyInstance,FastifyRequest} from "fastify";
import type {PoolClient} from "pg";
import {withTenant,uuid} from "../../database/src/index.js";
import {digest,enforcePermit,issueTestPermit,validateTestAuthority,verifyTestPermit,verifyStoredTestPermit,PermitError,PT_PROFILE,type PtClaims} from "../../pt/src/permit.js";
import {FIXTURE_ID,fixtureOperationFor} from "../../pt/src/fixture.js";
import {DETECTION_FIXTURE,PROFILES,isProfile} from "../../pt/src/security-fixture.js";
import {RULES,planRules,planFingerprint} from "../../pt/src/detection.js";
import {persistTerminalCoverage} from "../../pt/src/terminal-coverage.js";
import {persistOrchestrationTerminal} from "../../pt/src/orchestration-terminal.js";

export class PtError extends Error {constructor(public statusCode:number,public code:string){super(code);}}
const ID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
function id(x:unknown):string{if(typeof x!=="string"||!ID.test(x))throw new PtError(400,"INVALID_ID");return x;}
function obj(x:unknown):Record<string,unknown>{if(!x||typeof x!=="object"||Array.isArray(x))throw new PtError(400,"INVALID_BODY");return x as Record<string,unknown>;}
function strict(b:Record<string,unknown>,keys:string[]):void{
 if(Object.keys(b).some(k=>!keys.includes(k)))throw new PtError(400,"UNKNOWN_FIELD");
}
function number(x:unknown,low:number,high:number,name:string):number{
 if(!Number.isInteger(x)||(x as number)<low||(x as number)>high)throw new PtError(400,"INVALID_"+name);
 return x as number;
}
function names(x:unknown,name:string,max=20):string[]{
 if(!Array.isArray(x)||x.length<1||x.length>max||x.some(v=>typeof v!=="string"||v.length===0||v.length>255)||
  new Set(x).size!==x.length)throw new PtError(400,"INVALID_"+name);
 return x as string[];
}
function key(req:FastifyRequest):string{
 const value=req.headers["idempotency-key"];
 if(typeof value!=="string"||!/^[A-Za-z0-9:_-]{8,128}$/.test(value))throw new PtError(400,"IDEMPOTENCY_KEY_REQUIRED");
 return value;
}
function params(req:FastifyRequest,name="id"):string{return id((req.params as Record<string,unknown>)[name]);}
function queryLimit(req:FastifyRequest):number{
 const v=(req.query as {limit?:string}).limit;
 const n=v===undefined?50:Number(v);
 return number(n,1,100,"LIMIT");
}
function authority(req:FastifyRequest):void{
 try{validateTestAuthority(req.headers["x-pt-authority-key"]);}catch{throw new PtError(403,"TEST_AUTHORITY_REQUIRED");}
}
type Scope={
 id:string;tenant_id:string;target_id:string;specification_id:string;specification_version:number;
 spec_fingerprint:string;target_verification_version:number;target_scope_revision:number;
 environment:"SYNTHETIC";fixture_id:"billing-safe-v1"|"pt-security-v1";profile:typeof PT_PROFILE;
 operation_keys:string[];exclusions:string[];max_evaluations:number;max_concurrency:number;
 rate_per_minute:number;deadline_ms:number;validity_minutes:number;
};
type Target={id:string;environment:string;lifecycle:string;verification_version:number;scope_revision:number};
type Permit={id:string;scope_id:string;token_hash:string;claims:PtClaims;signed_body:string;expires_at:string;revoked_at:string|null;consumed:number;reserved:number};
async function scope(tx:PoolClient,sid:string):Promise<Scope>{
 const r=await tx.query("SELECT * FROM api_pt_scopes WHERE id=$1",[sid]);
 if(!r.rowCount)throw new PtError(404,"PT_SCOPE_NOT_FOUND");
 return r.rows[0] as Scope;
}
async function target(tx:PoolClient,tid:string,lock=false):Promise<Target>{
 const r=await tx.query("SELECT id,environment,lifecycle,verification_version,scope_revision FROM api_targets WHERE id=$1"+(lock?" FOR UPDATE":""),[tid]);
 if(!r.rowCount)throw new PtError(404,"TARGET_NOT_FOUND");
 return r.rows[0] as Target;
}
async function stop(tx:PoolClient,tenantId:string):Promise<boolean>{
 await tx.query("INSERT INTO api_pt_stop(tenant_id) VALUES($1) ON CONFLICT DO NOTHING",[tenantId]);
 const r=await tx.query("SELECT enabled FROM api_pt_stop WHERE tenant_id=$1 FOR UPDATE",[tenantId]);
 return r.rows[0]?.enabled===true;
}
async function record(tx:PoolClient,tenantId:string,subjectId:string,action:string,details:Record<string,unknown>={}):Promise<void>{
 await tx.query("INSERT INTO api_pt_events(id,tenant_id,subject_id,action,details) VALUES($1,$2,$3,$4,$5::jsonb)",[uuid(),tenantId,subjectId,action,JSON.stringify(details)]);
}
async function denied(tx:PoolClient,t:string,sid:string,code:string):Promise<{error:string;code:string}>{
 await tx.query("INSERT INTO api_pt_denials(id,tenant_id,scope_id,code,subject_id) VALUES($1,$2,$3,$4,$3)",[uuid(),t,sid,code]);
 await record(tx,t,sid,"PT_EXECUTION_DENIED",{code});
 return {error:code,code};
}
function checkBinding(c:PtClaims,s:Scope,t:Target,tid:string):void{
 if(t.lifecycle!=="ACTIVE"||t.environment!=="SYNTHETIC")throw new PermitError("TARGET_NOT_SYNTHETIC_ACTIVE");
 enforcePermit(c,{tenantId:tid,targetId:s.target_id,scopeId:s.id,specificationId:s.specification_id,
  specificationVersion:s.specification_version,specFingerprint:s.spec_fingerprint,
  targetVerificationVersion:t.verification_version,targetScopeRevision:t.scope_revision,fixtureId:s.fixture_id});
 if(c.maxEvaluations!==s.max_evaluations||c.maxConcurrency!==s.max_concurrency||
   c.ratePerMinute!==s.rate_per_minute||c.deadlineMs!==s.deadline_ms||
   JSON.stringify(c.operationKeys)!==JSON.stringify(s.operation_keys)||
   JSON.stringify(c.exclusions)!==JSON.stringify(s.exclusions))
  throw new PermitError("PERMIT_POLICY_MISMATCH");
}
async function permit(tx:PoolClient,sid:string,lock=false):Promise<Permit|null>{
 const r=await tx.query("SELECT * FROM api_pt_permits WHERE scope_id=$1"+(lock?" FOR UPDATE":""),[sid]);
 return r.rows[0] as Permit|undefined??null;
}
export function registerPtRoutes(app:FastifyInstance,identity:(req:FastifyRequest)=>string):void{
 app.get("/v6/pt/capabilities",async()=>({
  contract:"phase06-pt-control-v1",profile:PT_PROFILE,fixture:FIXTURE_ID,methods:["GET","HEAD"],
  customerNetworkRequests:0,productionHostAuthorization:"BLOCKED",syntheticFixtureOnly:true,
  hostIntegration:"NOT_FROZEN",verifiedFixedAuthority:false
 }));
 app.get("/v6/pt/targets/:id/fixtures",async req=>{
  const t=identity(req),tid=params(req);
  return withTenant(t,async tx=>{
   const x=await target(tx,tid);
   return {fixtureId:FIXTURE_ID,eligible:x.environment==="SYNTHETIC"&&x.lifecycle==="ACTIVE"&&process.env.NODE_ENV!=="production"&&process.env.PT_TEST_AUTHORITY_ENABLED==="true",
    permittedMethods:["GET","HEAD"],paths:["/bills","/status"],customerNetworkRequests:0};
  });
 });
 app.post("/v6/pt/targets/:id/scopes",async(req,reply)=>{
  const t=identity(req),tid=params(req),b=obj(req.body);
  strict(b,["specificationId","operationKeys","exclusions","maxEvaluations","maxConcurrency","ratePerMinute","deadlineMs","validityMinutes","fixtureId"]);
  const sid=id(b.specificationId),operationKeys=names(b.operationKeys,"OPERATIONS");
  const exclusions=b.exclusions===undefined?[]:Array.isArray(b.exclusions)?b.exclusions:null;
  if(!exclusions||exclusions.length>20||exclusions.some(x=>typeof x!=="string"||!(b.fixtureId===DETECTION_FIXTURE?["/pt/account","/pt/resources/bob","/pt/admin","/pt/confidential"]:["/bills","/status"]).includes(x))||
    new Set(exclusions).size!==exclusions.length)throw new PtError(400,"INVALID_EXCLUSIONS");
  const budget=number(b.maxEvaluations,1,30,"MAX_EVALUATIONS");
  const concurrency=number(b.maxConcurrency,1,2,"CONCURRENCY");
  const rate=number(b.ratePerMinute,1,20,"RATE");
  const deadline=number(b.deadlineMs,1000,30000,"DEADLINE");
  const validMinutes=number(b.validityMinutes,1,15,"VALIDITY");
  if(b.fixtureId!==FIXTURE_ID&&b.fixtureId!==DETECTION_FIXTURE)throw new PtError(400,"FIXTURE_NOT_SUPPORTED");
  const idempotency=key(req),newId=uuid();
  const result=await withTenant(t,async tx=>{
   const previous=await tx.query("SELECT * FROM api_pt_scopes WHERE target_id=$1 AND idempotency_key=$2",[tid,idempotency]);
   if(previous.rowCount){
    const p=previous.rows[0] as Scope;
    if(p.specification_id!==sid||p.fixture_id!==b.fixtureId||JSON.stringify(p.operation_keys)!==JSON.stringify(operationKeys)||
       JSON.stringify(p.exclusions)!==JSON.stringify(exclusions)||p.max_evaluations!==budget||
       p.max_concurrency!==concurrency||p.rate_per_minute!==rate||p.deadline_ms!==deadline||
       p.validity_minutes!==validMinutes)throw new PtError(409,"IDEMPOTENCY_CONFLICT");
    return {id:p.id,status:"CUSTOMER_PROPOSED",created:false};
   }
   const a=await target(tx,tid);
   if(a.lifecycle!=="ACTIVE"||a.environment!=="SYNTHETIC")throw new PtError(409,"SYNTHETIC_TARGET_ONLY");
   const i=await tx.query("SELECT version_number,raw_fingerprint FROM api_spec_inventories WHERE specification_id=$1 AND target_id=$2",[sid,tid]);
   if(!i.rowCount)throw new PtError(404,"IMPORTED_SPECIFICATION_NOT_FOUND");
   const r=await tx.query("SELECT operation_key,method,path FROM api_inventory_operations WHERE specification_id=$1",[sid]);
   const operations=new Map((r.rows as {operation_key:string;method:string;path:string}[]).map(x=>[x.operation_key,x]));
   for(const k of operationKeys){
    const op=operations.get(k);
    if(!op)throw new PtError(409,"OPERATION_OUT_OF_SCOPE");
    if(op.method!=="GET"&&op.method!=="HEAD")throw new PtError(409,"METHOD_DENIED");
    if(!fixtureOperationFor(b.fixtureId as string,op.method,op.path))throw new PtError(409,"FIXTURE_OPERATION_NOT_ALLOWED");
   }
   await tx.query("INSERT INTO api_pt_scopes(id,tenant_id,target_id,specification_id,specification_version,spec_fingerprint,target_verification_version,target_scope_revision,environment,fixture_id,profile,operation_keys,exclusions,max_evaluations,max_concurrency,rate_per_minute,deadline_ms,validity_minutes,idempotency_key) VALUES($1,$2,$3,$4,$5,$6,$7,$8,'SYNTHETIC',$9,$10,$11::jsonb,$12::jsonb,$13,$14,$15,$16,$17,$18)",
    [newId,t,tid,sid,i.rows[0].version_number,i.rows[0].raw_fingerprint,a.verification_version,a.scope_revision,
     b.fixtureId,PT_PROFILE,JSON.stringify(operationKeys),JSON.stringify(exclusions),budget,concurrency,rate,deadline,validMinutes,idempotency]);
   await record(tx,t,newId,"PT_SCOPE_PROPOSED",{specificationId:sid,fixtureId:FIXTURE_ID,mode:PT_PROFILE});
   return {id:newId,status:"CUSTOMER_PROPOSED",created:true};
  });
  reply.code(result.created?201:200).send(result);
 });
 app.get("/v6/pt/targets/:id/scopes",async req=>{
  const t=identity(req),tid=params(req),limit=queryLimit(req);
  return withTenant(t,async tx=>{
   await target(tx,tid);
   const r=await tx.query("SELECT s.*,p.id AS permit_id,p.revoked_at,p.expires_at FROM api_pt_scopes s LEFT JOIN api_pt_permits p ON p.scope_id=s.id AND p.tenant_id=s.tenant_id WHERE s.target_id=$1 ORDER BY s.created_at DESC LIMIT $2",[tid,limit]);
   return r.rows.map(x=>({...x,signed_token:undefined}));
  });
 });
 app.get("/v6/pt/scopes/:id",async req=>{
  const t=identity(req),sid=params(req);
  return withTenant(t,async tx=>{
   const s=await scope(tx,sid);
   const p=await permit(tx,sid);
   const request=await tx.query("SELECT 1 FROM api_pt_requests WHERE scope_id=$1",[sid]);
   return {scope:s,requested:!!request.rowCount,permit:p?{id:p.id,tokenHash:p.token_hash,
    revoked:!!p.revoked_at,expired:new Date(p.expires_at).getTime()<=Date.now(),expiresAt:p.expires_at,
    consumed:p.consumed,reserved:p.reserved}:null,realHostExecution:"BLOCKED"};
  });
 });
 app.post("/v6/pt/scopes/:id/request-authorization",async(req,reply)=>{
  const t=identity(req),sid=params(req);
  const result=await withTenant(t,async tx=>{
   const s=await scope(tx,sid),existing=await tx.query("SELECT * FROM api_pt_requests WHERE scope_id=$1",[sid]);
   if(existing.rowCount)return {id:existing.rows[0].id,scopeId:sid,status:"PENDING_TEST_AUTHORITY",created:false};
   const tid=uuid(),fingerprint=digest(JSON.stringify(s));
   await tx.query("INSERT INTO api_pt_requests(id,tenant_id,scope_id,request_fingerprint) VALUES($1,$2,$3,$4)",[tid,t,sid,fingerprint]);
   await record(tx,t,sid,"PT_AUTHORIZATION_REQUESTED");
   return {id:tid,scopeId:sid,status:"PENDING_TEST_AUTHORITY",created:true};
  });
  reply.code(result.created?201:200).send(result);
 });
 app.post("/v6/pt/test-authority/scopes/:id/issue",async(req,reply)=>{
  authority(req);
  const t=identity(req),sid=params(req);
  const result=await withTenant(t,async tx=>{
   if(await stop(tx,t))throw new PtError(409,"EMERGENCY_STOP_ACTIVE");
   const s=await scope(tx,sid),targetNow=await target(tx,s.target_id,true);
   if(targetNow.lifecycle!=="ACTIVE"||targetNow.environment!=="SYNTHETIC"||
      targetNow.verification_version!==s.target_verification_version||targetNow.scope_revision!==s.target_scope_revision)
    throw new PtError(409,"SCOPE_TARGET_STALE");
   const request=await tx.query("SELECT 1 FROM api_pt_requests WHERE scope_id=$1",[sid]);
   if(!request.rowCount)throw new PtError(409,"AUTHORIZATION_NOT_REQUESTED");
   const old=await permit(tx,sid);
   if(old)return {id:old.id,status:old.revoked_at?"REVOKED":"ISSUED",expiresAt:old.expires_at,tokenHash:old.token_hash,created:false};
   const now=Date.now(),pid=uuid();
   const operations=await tx.query("SELECT operation_key,method,path FROM api_inventory_operations WHERE specification_id=$1",[s.specification_id]);
   const selected=(operations.rows as {operation_key:string;method:string;path:string}[]).filter(x=>s.operation_keys.includes(x.operation_key));
   if(selected.length!==s.operation_keys.length||selected.some(x=>!fixtureOperationFor(s.fixture_id,x.method,x.path)))
    throw new PtError(409,"SCOPE_OPERATIONS_STALE");
   const claims:Omit<PtClaims,"v"|"issuer"|"audience"|"profile"|"nonce">={
    permitId:pid,tenantId:t,targetId:s.target_id,environment:"SYNTHETIC",fixtureId:s.fixture_id,
    specificationId:s.specification_id,specificationVersion:s.specification_version,
    specFingerprint:s.spec_fingerprint,targetVerificationVersion:s.target_verification_version,
    targetScopeRevision:s.target_scope_revision,scopeId:s.id,operationKeys:s.operation_keys,
    methods:["GET","HEAD"],exclusions:s.exclusions,maxEvaluations:s.max_evaluations,
    maxConcurrency:s.max_concurrency,ratePerMinute:s.rate_per_minute,deadlineMs:s.deadline_ms,
    notBefore:now-(s.validity_minutes===15?0:1000),expiresAt:now+s.validity_minutes*60000
   };
   let token;
   try{token=issueTestPermit(claims);}catch{throw new PtError(403,"TEST_AUTHORITY_DISABLED");}
   let c:PtClaims;
   try{c=verifyTestPermit(token);}catch(e){throw new PtError(409,e instanceof PermitError?e.code:"TEST_PERMIT_VERIFICATION_FAILED");}
   await tx.query("INSERT INTO api_pt_permits(id,tenant_id,scope_id,token_hash,claims,signed_body,issued_at,expires_at) VALUES($1,$2,$3,$4,$5::jsonb,$6,to_timestamp($7::double precision/1000),to_timestamp($8::double precision/1000))",
    [pid,t,sid,digest(token),JSON.stringify(c),token.split(".")[1],now,c.expiresAt]);
   await record(tx,t,pid,"TEST_ONLY_PERMIT_ISSUED",{scopeId:sid,tokenHash:digest(token)});
   return {id:pid,status:"ISSUED",expiresAt:new Date(c.expiresAt).toISOString(),tokenHash:digest(token),created:true};
  });
  reply.code(result.created?201:200).send(result);
 });
 app.get("/v6/pt/permits/:id",async req=>{
  const t=identity(req),pid=params(req);
  return withTenant(t,async tx=>{
   const x=await tx.query("SELECT id,scope_id,token_hash,expires_at,revoked_at,consumed,reserved,rate_used FROM api_pt_permits WHERE id=$1",[pid]);
   if(!x.rowCount)throw new PtError(404,"PERMIT_NOT_FOUND");
   return {...x.rows[0],state:x.rows[0].revoked_at?"REVOKED":new Date(x.rows[0].expires_at).getTime()<=Date.now()?"EXPIRED":"SYNTHETIC_TEST_ONLY_VALID",realHostAuthorization:false};
  });
 });
 app.post("/v6/pt/test-authority/permits/:id/revoke",async req=>{
  authority(req);const t=identity(req),pid=params(req);
  return withTenant(t,async tx=>{
   if(await stop(tx,t))throw new PtError(409,"EMERGENCY_STOP_ACTIVE");
   const p=await tx.query("SELECT id,revoked_at FROM api_pt_permits WHERE id=$1 FOR UPDATE",[pid]);
   if(!p.rowCount)throw new PtError(404,"PERMIT_NOT_FOUND");
   if(!p.rows[0].revoked_at){
    await tx.query("UPDATE api_pt_permits SET revoked_at=now() WHERE id=$1",[pid]);
    await record(tx,t,pid,"TEST_PERMIT_REVOKED");
   }
   return {id:pid,state:"REVOKED"};
  });
 });
 app.post("/v6/pt/scopes/:id/jobs",async(req,reply)=>{
  const t=identity(req),sid=params(req),b=obj(req.body);
  strict(b,["operationKeys"]);
  const operations=names(b.operationKeys,"OPERATIONS");
  const idem=key(req),newJob=uuid();
  const result=await withTenant(t,async tx=>{
   const s=await scope(tx,sid);
   if(s.fixture_id!==FIXTURE_ID)throw new PtError(409,"USE_PHASE07_DETECTION_ROUTE");
   // Serialize ALL admission and replay lookups per tenant on the shared stop row.
   // Otherwise competing equal idempotency keys can both pass an unguarded SELECT.
   const halted=await stop(tx,t);
   const previous=await tx.query("SELECT j.*,a.idempotency_key FROM api_pt_jobs j JOIN api_assessments a ON a.id=j.assessment_id WHERE j.tenant_id=$1 AND a.idempotency_key=$2",[t,idem]);
   if(previous.rowCount){
    const old=previous.rows[0];
    if(old.scope_id!==sid||JSON.stringify(old.operation_keys)!==JSON.stringify(operations))throw new PtError(409,"IDEMPOTENCY_CONFLICT");
    return {id:old.assessment_id,status:"QUEUED_OR_PROCESSING",created:false};
   }
   if(halted)return denied(tx,t,sid,"EMERGENCY_STOP_ACTIVE");
   const targetNow=await target(tx,s.target_id,true);
   const p=await permit(tx,sid,true);
   if(!p)return denied(tx,t,sid,"AUTHORIZATION_MISSING");
   if(p.revoked_at)return denied(tx,t,sid,"PERMIT_REVOKED");
   let claims:PtClaims;
   try{
    claims=verifyStoredTestPermit(p.claims,p.token_hash,p.signed_body);
    if(claims.permitId!==p.id)throw new PermitError("PERMIT_INTEGRITY_MISMATCH");
    checkBinding(claims,s,targetNow,t);
   }catch(e){return denied(tx,t,sid,e instanceof PermitError?e.code:"PERMIT_INVALID");}
   if(operations.some(x=>!s.operation_keys.includes(x)))return denied(tx,t,sid,"OPERATION_OUT_OF_SCOPE");
   const r=await tx.query("SELECT operation_key,method,path FROM api_inventory_operations WHERE specification_id=$1 AND operation_key=ANY($2::text[])",[s.specification_id,operations]);
   if(r.rowCount!==operations.length)return denied(tx,t,sid,"OPERATION_STALE");
   if(r.rows.some(x=>!fixtureOperationFor(s.fixture_id,x.method,x.path)))return denied(tx,t,sid,"METHOD_OR_FIXTURE_DENIED");
   if(r.rows.some(x=>s.exclusions.includes(x.path)))return denied(tx,t,sid,"PATH_EXCLUDED");
   if(p.consumed+p.reserved>=s.max_evaluations)return denied(tx,t,sid,"PERMIT_BUDGET_EXHAUSTED");
   const active=await tx.query("SELECT count(*)::int AS tenant_active,count(*) FILTER(WHERE j.target_id=$1)::int AS target_active,count(*) FILTER(WHERE j.permit_id=$2)::int AS permit_active FROM api_pt_jobs j JOIN api_assessments a ON a.id=j.assessment_id WHERE j.tenant_id=$3 AND a.status IN('QUEUED','PROCESSING')",[s.target_id,p.id,t]);
   const counters=active.rows[0];
   if(counters.tenant_active>=3||counters.target_active>=2||counters.permit_active>=s.max_concurrency)return denied(tx,t,sid,"CONCURRENCY_LIMIT");
   await tx.query("INSERT INTO api_assessments(id,tenant_id,target_id,specification_id,status,mode,idempotency_key,engine_version,inventory_version,inventory_raw_fingerprint,inventory_fingerprint) SELECT $1,$2,$3,$4,'QUEUED','SYNTHETIC_PT_FIXTURE',$5,'pt-fixture-v1',i.version_number,i.raw_fingerprint,i.normalized_fingerprint FROM api_spec_inventories i WHERE i.specification_id=$4",
    [newJob,t,s.target_id,s.specification_id,idem]);
   await tx.query("INSERT INTO api_pt_jobs(assessment_id,tenant_id,target_id,scope_id,permit_id,operation_keys,job_deadline) VALUES($1,$2,$3,$4,$5,$6::jsonb,now()+($7::text||' milliseconds')::interval)",
    [newJob,t,s.target_id,sid,p.id,JSON.stringify(operations),s.deadline_ms]);
   await tx.query("SELECT public.api_enqueue_assessment($1)",[newJob]);
   await record(tx,t,newJob,"PT_FIXTURE_JOB_QUEUED",{permitId:p.id,operations:operations.length});
   return {id:newJob,status:"QUEUED",created:true,customerNetworkRequests:0};
  });
  if("error" in result)reply.code(409).send(result);
  else reply.code(result.created?201:200).send(result);
 });
 app.get("/v6/pt/jobs/:id",async req=>{
  const t=identity(req),jid=params(req);
  return withTenant(t,async tx=>{
   const r=await tx.query("SELECT a.id,a.status,a.error_code AS \"errorCode\",a.created_at,a.completed_at,j.scope_id,j.permit_id,j.operation_keys,j.job_deadline,p.consumed,p.reserved,p.rate_used,s.max_evaluations FROM api_pt_jobs j JOIN api_assessments a ON a.id=j.assessment_id JOIN api_pt_permits p ON p.id=j.permit_id JOIN api_pt_scopes s ON s.id=j.scope_id WHERE j.assessment_id=$1",[jid]);
   if(!r.rowCount)throw new PtError(404,"PT_JOB_NOT_FOUND");
   const receipts=await tx.query("SELECT decision,count(*)::int AS n FROM api_pt_receipts WHERE assessment_id=$1 GROUP BY decision",[jid]);
   return {...r.rows[0],counts:Object.fromEntries(receipts.rows.map(x=>[x.decision,x.n])),customerNetworkRequests:0};
  });
 });
 app.get("/v6/pt/jobs/:id/receipts",async req=>{
  const t=identity(req),jid=params(req),limit=queryLimit(req);
  return withTenant(t,async tx=>{
   const check=await tx.query("SELECT 1 FROM api_pt_jobs WHERE assessment_id=$1",[jid]);
   if(!check.rowCount)throw new PtError(404,"PT_JOB_NOT_FOUND");
   const r=await tx.query("SELECT id,operation_key,method,path,fixture_id,specification_version,scope_revision,permit_hash,evaluation_sequence,budget_remaining,decision,outcome,code,http_status,response_bytes,response_hash,duration_ms,budget_consumed,created_at FROM api_pt_receipts WHERE assessment_id=$1 ORDER BY created_at,id LIMIT $2",[jid,limit]);
   return r.rows;
  });
 });
 app.get("/v6/pt/jobs/:id/report",async req=>{
  const t=identity(req),jid=params(req);
  return withTenant(t,async tx=>{
   const x=await tx.query("SELECT r.projection FROM api_pt_reports r JOIN api_pt_jobs j ON j.assessment_id=r.assessment_id WHERE r.assessment_id=$1",[jid]);
   if(!x.rowCount)throw new PtError(409,"PT_REPORT_NOT_READY_OR_NOT_FOUND");
   return x.rows[0].projection;
  });
 });
 app.get("/v6/pt/targets/:id/history",async req=>{
  const t=identity(req),tid=params(req),limit=queryLimit(req);
  return withTenant(t,async tx=>{
   await target(tx,tid);
   const r=await tx.query("SELECT a.id,a.status,a.error_code,j.scope_id,j.permit_id,a.created_at,a.completed_at FROM api_pt_jobs j JOIN api_assessments a ON a.id=j.assessment_id WHERE j.target_id=$1 ORDER BY a.created_at DESC LIMIT $2",[tid,limit]);
   return r.rows;
  });
 });
 app.get("/v6/pt/scopes/:id/denials",async req=>{
  const t=identity(req),sid=params(req),limit=queryLimit(req);
  return withTenant(t,async tx=>{
   await scope(tx,sid);
   return (await tx.query("SELECT id,code,occurred_at FROM api_pt_denials WHERE scope_id=$1 ORDER BY occurred_at DESC LIMIT $2",[sid,limit])).rows;
  });
 });
 app.post("/v6/pt/jobs/:id/cancel",async req=>{
  const t=identity(req),jid=params(req);
  return withTenant(t,async tx=>{
   const j=await tx.query("SELECT 1 FROM api_pt_jobs WHERE assessment_id=$1",[jid]);
   if(!j.rowCount)throw new PtError(404,"PT_JOB_NOT_FOUND");
   const c=await tx.query("SELECT public.api_cancel_assessment($1) AS success",[jid]);
   if(!c.rows[0]?.success)throw new PtError(409,"PT_JOB_NOT_CANCELLABLE");
   await persistTerminalCoverage(tx,t,jid);
   await persistOrchestrationTerminal(tx,t,jid,"CANCELLED","CUSTOMER_CANCELLED");
   await tx.query("UPDATE api_pt9_stages SET status='CANCELLED',reason='CUSTOMER_CANCELLED',finished_at=now() WHERE assessment_id=$1 AND status IN('PENDING','RUNNING')",[jid]);
   await record(tx,t,jid,"PT_JOB_CANCELLED");
   return {id:jid,status:"CANCELLED"};
  });
 });
 app.get("/v6/pt/stop",async req=>{
  const t=identity(req);
  return withTenant(t,async tx=>{
   const s=await tx.query("SELECT enabled,updated_at,generation FROM api_pt_stop WHERE tenant_id=$1",[t]);
   return s.rows[0]??{enabled:false,generation:0};
  });
 });
 app.post("/v6/pt/test-authority/stop",async req=>{
  authority(req);const t=identity(req);
  return withTenant(t,async tx=>{
   await stop(tx,t);
   await tx.query("UPDATE api_pt_stop SET enabled=true,updated_at=now(),generation=generation+1 WHERE tenant_id=$1",[t]);
   await tx.query("UPDATE api_pt_permits SET revoked_at=now() WHERE tenant_id=$1 AND revoked_at IS NULL",[t]);
   const jobs=await tx.query("SELECT j.assessment_id FROM api_pt_jobs j JOIN api_assessments a ON a.id=j.assessment_id WHERE j.tenant_id=$1 AND a.status IN('QUEUED','PROCESSING')",[t]);
   for(const j of jobs.rows){
    await tx.query("SELECT public.api_cancel_assessment($1)",[j.assessment_id]);
    await persistTerminalCoverage(tx,t,j.assessment_id as string);
    await persistOrchestrationTerminal(tx,t,j.assessment_id as string,"CANCELLED","EMERGENCY_STOP");
    await tx.query("UPDATE api_pt9_stages SET status='CANCELLED',reason='EMERGENCY_STOP',finished_at=now() WHERE assessment_id=$1 AND status IN('PENDING','RUNNING')",[j.assessment_id]);
   }
   await record(tx,t,t,"PT_EMERGENCY_STOP",{cancelledJobs:jobs.rowCount});
   return {enabled:true,cancelledJobs:jobs.rowCount};
  });
 });
 app.post("/v6/pt/test-authority/resume",async req=>{
  authority(req);const t=identity(req);
  return withTenant(t,async tx=>{
   await stop(tx,t);
   await tx.query("UPDATE api_pt_stop SET enabled=false,updated_at=now(),generation=generation+1 WHERE tenant_id=$1",[t]);
   await record(tx,t,t,"PT_TEST_AUTHORITY_RESUME");
   return {enabled:false,notice:"Previously revoked permits remain revoked"};
  });
 });

 // Phase07: additive isolated synthetic detection admission. Legacy Phase06 jobs stay unchanged.
 app.get("/v7/pt/rules",async()=>({engine:"pt-detection-v1",fixtureId:DETECTION_FIXTURE,
  rules:RULES.map(r=>({id:r.id,revision:r.revision,category:r.category,path:r.path,
   requiredIdentities:r.cases.map(x=>x.actor),evaluations:r.cases.length,impact:r.impact,
   description:r.description,remediation:r.remediation})),productionHostAuthorization:"BLOCKED",customerNetworkRequests:0}));
 app.get("/v7/pt/fixtures",async()=>({fixtureId:DETECTION_FIXTURE,fixtureVersion:1,profiles:PROFILES,
  paths:["/pt/account","/pt/resources/bob","/pt/admin","/pt/confidential"],methods:["GET","HEAD"],
  identities:["anonymous","alice","bob","admin","invalid","expired","revoked"],
  trustedExpectedPolicy:"REPOSITORY_OWNED_VERSIONED_ORACLE",customerNetworkRequests:0}));
 app.post("/v7/pt/scopes/:id/detections",async(req,reply)=>{
  const t=identity(req),sid=params(req),b=obj(req.body);
  strict(b,["profile","ruleIds"]);
  if(!isProfile(b.profile))throw new PtError(400,"UNSUPPORTED_TRUSTED_PROFILE");
  const profile=b.profile;
  let selected:ReturnType<typeof planRules>;
  try{selected=planRules(names(b.ruleIds,"RULES",RULES.length));}
  catch(error){
   if(error instanceof Error&&["INVALID_DETECTION_RULE_SELECTION","UNKNOWN_DETECTION_RULE"].includes(error.message))
    throw new PtError(400,error.message);
   throw error;
  }
  const idem=key(req),newJob=uuid();
  const result=await withTenant(t,async tx=>{
   const s=await scope(tx,sid);
   if(s.fixture_id!==DETECTION_FIXTURE)throw new PtError(409,"PT7_TRUSTED_FIXTURE_REQUIRED");
   const ops=await tx.query("SELECT operation_key,method,path FROM api_inventory_operations WHERE specification_id=$1 AND method='GET'",[s.specification_id]);
   const byPath=new Map((ops.rows as {operation_key:string;method:string;path:string}[]).map(x=>[x.path,x]));
   const selectedKeys:string[]=[];
   const evaluations:{evaluationKey:string;ruleId:string;caseId:string;operationKey:string;method:"GET";path:string;actor:string}[]=[];
   for(const rule of selected){
    const op=byPath.get(rule.path);
    if(!op||!s.operation_keys.includes(op.operation_key)||s.exclusions.includes(rule.path))
     throw new PtError(409,"DETECTION_OPERATION_OUT_OF_SCOPE");
    if(!fixtureOperationFor(DETECTION_FIXTURE,op.method,op.path))
     throw new PtError(409,"DETECTION_FIXTURE_OPERATION_DENIED");
    if(!selectedKeys.includes(op.operation_key))selectedKeys.push(op.operation_key);
    for(const testCase of rule.cases){
     evaluations.push({evaluationKey:rule.id+":"+testCase.caseId,ruleId:rule.id,
      caseId:testCase.caseId,operationKey:op.operation_key,method:"GET",path:rule.path,actor:testCase.actor});
    }
   }
   if(evaluations.length>20||evaluations.length>s.max_evaluations)
    throw new PtError(409,"DETECTION_BUDGET_PREVIEW_EXCEEDS_SCOPE");
   const plannedRules=selected.map(x=>({id:x.id,revision:x.revision}));
   const plan={engineVersion:"pt-detection-v1",fixtureVersion:1,fixtureId:DETECTION_FIXTURE,
    profile,rules:plannedRules,evaluations,specFingerprint:s.spec_fingerprint,scopeId:s.id};
   const fingerprint=planFingerprint(plan);
   const halted=await stop(tx,t);
   const existing=await tx.query("SELECT a.id,p.plan_fingerprint FROM api_assessments a JOIN api_pt_detection_plans p ON p.assessment_id=a.id AND p.tenant_id=a.tenant_id WHERE a.tenant_id=$1 AND a.idempotency_key=$2",[t,idem]);
   if(existing.rowCount){
    if(existing.rows[0].plan_fingerprint!==fingerprint)throw new PtError(409,"IDEMPOTENCY_CONFLICT");
    return {id:existing.rows[0].id,status:"QUEUED_OR_PROCESSING",created:false};
   }
   if(halted)return denied(tx,t,sid,"EMERGENCY_STOP_ACTIVE");
   const current=await target(tx,s.target_id,true),p=await permit(tx,sid,true);
   if(!p)return denied(tx,t,sid,"AUTHORIZATION_MISSING");
   if(p.revoked_at)return denied(tx,t,sid,"PERMIT_REVOKED");
   try{
    const claims=verifyStoredTestPermit(p.claims,p.token_hash,p.signed_body);
    if(claims.permitId!==p.id)throw new PermitError("PERMIT_INTEGRITY_MISMATCH");
    checkBinding(claims,s,current,t);
   }catch(e){return denied(tx,t,sid,e instanceof PermitError?e.code:"PERMIT_INVALID");}
   if(evaluations.length>p.claims.maxEvaluations-p.consumed-p.reserved)
    return denied(tx,t,sid,"PERMIT_BUDGET_EXHAUSTED");
   if(evaluations.length>s.rate_per_minute)
    return denied(tx,t,sid,"DETECTION_RATE_BUDGET_TOO_SMALL");
   const active=await tx.query("SELECT count(*)::int AS tenant_active,count(*) FILTER(WHERE j.target_id=$1)::int AS target_active,count(*) FILTER(WHERE j.permit_id=$2)::int AS permit_active FROM api_pt_jobs j JOIN api_assessments a ON a.id=j.assessment_id WHERE j.tenant_id=$3 AND a.status IN('QUEUED','PROCESSING')",[s.target_id,p.id,t]);
   if(active.rows[0].tenant_active>=3||active.rows[0].target_active>=2||active.rows[0].permit_active>=s.max_concurrency)
    return denied(tx,t,sid,"CONCURRENCY_LIMIT");
   await tx.query("INSERT INTO api_assessments(id,tenant_id,target_id,specification_id,status,mode,idempotency_key,engine_version,inventory_version,inventory_raw_fingerprint,inventory_fingerprint) SELECT $1,$2,$3,$4,'QUEUED','SYNTHETIC_PT_FIXTURE',$5,'pt-detection-v1',i.version_number,i.raw_fingerprint,i.normalized_fingerprint FROM api_spec_inventories i WHERE i.specification_id=$4",
    [newJob,t,s.target_id,s.specification_id,idem]);
   await tx.query("INSERT INTO api_pt_jobs(assessment_id,tenant_id,target_id,scope_id,permit_id,operation_keys,job_deadline) VALUES($1,$2,$3,$4,$5,$6::jsonb,now()+($7::text||' milliseconds')::interval)",
    [newJob,t,s.target_id,sid,p.id,JSON.stringify(selectedKeys),s.deadline_ms]);
   await tx.query("INSERT INTO api_pt_detection_plans(assessment_id,tenant_id,fixture_version,fixture_profile,engine_version,rules,evaluations,plan_fingerprint) VALUES($1,$2,1,$3,'pt-detection-v1',$4::jsonb,$5::jsonb,$6)",
    [newJob,t,profile,JSON.stringify(plannedRules),JSON.stringify(evaluations),fingerprint]);
   await tx.query("SELECT public.api_enqueue_assessment($1)",[newJob]);
   await record(tx,t,newJob,"PT7_DETECTION_QUEUED",{permitId:p.id,rules:selected.length,evaluations:evaluations.length,planFingerprint:fingerprint});
   return {id:newJob,status:"QUEUED",created:true,plannedEvaluations:evaluations.length,planFingerprint:fingerprint,customerNetworkRequests:0};
  });
  if("error" in result)reply.code(409).send(result);
  else reply.code(result.created?201:200).send(result);
 });
 app.get("/v7/pt/jobs/:id",async req=>{
  const t=identity(req),jid=params(req);
  return withTenant(t,async tx=>{
   const q=await tx.query("SELECT a.id,a.status,a.error_code AS \"errorCode\",p.fixture_profile,p.rules,p.evaluations,p.plan_fingerprint,j.permit_id,j.scope_id,j.target_id FROM api_pt_detection_plans p JOIN api_assessments a ON a.id=p.assessment_id AND a.tenant_id=p.tenant_id JOIN api_pt_jobs j ON j.assessment_id=p.assessment_id WHERE p.assessment_id=$1",[jid]);
   if(!q.rowCount)throw new PtError(404,"DETECTION_JOB_NOT_FOUND");
   const n=await tx.query("SELECT state,count(*)::int AS n FROM api_pt_detection_evaluations WHERE assessment_id=$1 GROUP BY state",[jid]);
   return {...q.rows[0],counts:Object.fromEntries(n.rows.map(x=>[x.state,x.n])),customerNetworkRequests:0};
  });
 });
 app.get("/v7/pt/jobs/:id/evaluations",async req=>{
  const t=identity(req),jid=params(req),limit=queryLimit(req);
  return withTenant(t,async tx=>{
   const present=await tx.query("SELECT 1 FROM api_pt_detection_plans WHERE assessment_id=$1",[jid]);
   if(!present.rowCount)throw new PtError(404,"DETECTION_JOB_NOT_FOUND");
   return (await tx.query("SELECT id,evaluation_key,operation_key,method,path,actor,state,evidence,reason,created_at,settled_at FROM api_pt_detection_evaluations WHERE assessment_id=$1 ORDER BY evaluation_key LIMIT $2",[jid,limit])).rows;
  });
 });
 app.get("/v7/pt/jobs/:id/findings",async req=>{
  const t=identity(req),jid=params(req),limit=queryLimit(req);
  return withTenant(t,async tx=>{
   const present=await tx.query("SELECT 1 FROM api_pt_detection_plans WHERE assessment_id=$1",[jid]);
   if(!present.rowCount)throw new PtError(404,"DETECTION_JOB_NOT_FOUND");
   return (await tx.query("SELECT rule_id,rule_revision,status,code,fingerprint,evidence FROM api_pt_detection_results WHERE assessment_id=$1 AND status='OBSERVED' ORDER BY rule_id LIMIT $2",[jid,limit])).rows;
  });
 });
 app.get("/v7/pt/jobs/:id/coverage",async req=>{
  const t=identity(req),jid=params(req);
  return withTenant(t,async tx=>{
   const present=await tx.query("SELECT 1 FROM api_pt_detection_plans WHERE assessment_id=$1",[jid]);
   if(!present.rowCount)throw new PtError(404,"DETECTION_JOB_NOT_FOUND");
   return (await tx.query("SELECT rule_id,rule_revision,status,code,fingerprint FROM api_pt_detection_results WHERE assessment_id=$1 ORDER BY rule_id",[jid])).rows;
  });
 });
 app.get("/v8/pt/jobs/:id/terminal-coverage",async req=>{
  const t=identity(req),jid=params(req);
  return withTenant(t,async tx=>{
   const present=await tx.query("SELECT a.status FROM api_pt_detection_plans p JOIN api_assessments a ON a.id=p.assessment_id AND a.tenant_id=p.tenant_id WHERE p.assessment_id=$1",[jid]);
   if(!present.rowCount)throw new PtError(404,"DETECTION_JOB_NOT_FOUND");
   if(!["FAILED","CANCELLED"].includes(present.rows[0].status))throw new PtError(409,"TERMINAL_COVERAGE_NOT_READY");
   const found=await tx.query("SELECT projection FROM api_pt8_terminal_coverage WHERE assessment_id=$1",[jid]);
   if(!found.rowCount)throw new PtError(409,"TERMINAL_COVERAGE_UNAVAILABLE");
   return found.rows[0].projection;
  });
 });
 app.get("/v7/pt/jobs/:id/report",async req=>{
  const t=identity(req),jid=params(req);
  return withTenant(t,async tx=>{
   const r=await tx.query("SELECT projection FROM api_pt_detection_reports WHERE assessment_id=$1",[jid]);
   if(!r.rowCount)throw new PtError(409,"DETECTION_REPORT_NOT_READY");
   return r.rows[0].projection;
  });
 });
 app.get("/v7/pt/jobs/:id/export",async(req,reply)=>{
  const t=identity(req),jid=params(req);
  const report=await withTenant(t,async tx=>{
   const r=await tx.query("SELECT projection FROM api_pt_detection_reports WHERE assessment_id=$1",[jid]);
   if(!r.rowCount)throw new PtError(409,"DETECTION_REPORT_NOT_READY");
   return r.rows[0].projection as Record<string,unknown>;
  });
  reply.header("content-disposition","attachment; filename=synthetic-detection-"+jid+".json");
  reply.type("application/json").send(report);
 });
 app.get("/v7/pt/targets/:id/history",async req=>{
  const t=identity(req),tid=params(req),limit=queryLimit(req);
  return withTenant(t,async tx=>{
   await target(tx,tid);
   return (await tx.query("SELECT a.id,a.status,a.error_code,p.fixture_profile,p.plan_fingerprint,a.created_at,a.completed_at FROM api_pt_detection_plans p JOIN api_assessments a ON a.id=p.assessment_id JOIN api_pt_jobs j ON j.assessment_id=p.assessment_id WHERE j.target_id=$1 ORDER BY a.created_at DESC LIMIT $2",[tid,limit])).rows;
  });
 });
 app.get("/v7/pt/jobs/:id/compare/:otherId",async req=>{
  const t=identity(req),jid=params(req),other=params(req,"otherId");
  return withTenant(t,async tx=>{
   const r=await tx.query("SELECT p.assessment_id,p.fixture_version,p.rules,p.fixture_profile,j.scope_id,j.target_id,j.scope_id,s.spec_fingerprint,r.projection FROM api_pt_detection_plans p JOIN api_pt_jobs j ON j.assessment_id=p.assessment_id JOIN api_pt_scopes s ON s.id=j.scope_id JOIN api_pt_detection_reports r ON r.assessment_id=p.assessment_id WHERE p.assessment_id=ANY($1::uuid[])",[[jid,other]]);
   if(r.rowCount!==2)throw new PtError(409,"COMPARISON_REQUIRES_COMPLETED_REPORTS");
   const a=r.rows.find(x=>x.assessment_id===jid)!,b=r.rows.find(x=>x.assessment_id===other)!;
   if(a.target_id!==b.target_id||a.spec_fingerprint!==b.spec_fingerprint||a.fixture_version!==b.fixture_version||
    JSON.stringify(a.rules)!==JSON.stringify(b.rules))
    return {compatibility:"INCOMPATIBLE_SNAPSHOT",verifiedFixed:false,customerNetworkRequests:0};
   const before=(a.projection as {observations:{ruleId:string;fingerprint:string}[]}).observations;
   const after=(b.projection as {observations:{ruleId:string;fingerprint:string}[]}).observations;
   const left=new Map(before.map(x=>[x.ruleId,x.fingerprint])),right=new Map(after.map(x=>[x.ruleId,x.fingerprint]));
   return {compatibility:"COMPATIBLE",newlyObserved:after.filter(x=>!left.has(x.ruleId)).map(x=>x.ruleId),
    stillObserved:after.filter(x=>left.get(x.ruleId)===x.fingerprint).map(x=>x.ruleId),
    evidenceChanged:after.filter(x=>left.has(x.ruleId)&&left.get(x.ruleId)!==x.fingerprint).map(x=>x.ruleId),
    noLongerObserved:before.filter(x=>!right.has(x.ruleId)).map(x=>x.ruleId),
    verifiedFixed:false,customerNetworkRequests:0,limitation:"Disappeared synthetic observations are not VERIFIED_FIXED"};
  });
 });

}
