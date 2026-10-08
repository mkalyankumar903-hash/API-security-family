import type {FastifyInstance,FastifyRequest} from "fastify";
import type {PoolClient} from "pg";
import {withTenant,uuid} from "../../database/src/index.js";
import {TargetInputError,canonicalTargetUrl,checkName,checkEnvironment,checkRevision,checkScope,checkCredentialReference,sha256,nonce,signSynthetic,verifySynthetic,fixtureSigningKey,type SyntheticClaims} from "../../targets/src/contracts.js";

export class OnboardingError extends Error {constructor(public statusCode:number,public code:string){super(code);}}
const id=(v:unknown):string=>typeof v==="string"&&/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i.test(v)?v:bad(400,"INVALID_ID");
const bad=(status:number,code:string):never=>{throw new OnboardingError(status,code);};
const data=(v:unknown):Record<string,unknown>=>v&&typeof v==="object"&&!Array.isArray(v)?v as Record<string,unknown>:bad(400,"INVALID_BODY");
type Target={id:string;name:string;base_url:string;environment:string;revision:number;scope_revision:number;verification_version:number;lifecycle:string;ownership_status:string};
async function locked(tx:PoolClient,target:string):Promise<Target>{
 const r=await tx.query("SELECT * FROM api_targets WHERE id=$1 FOR UPDATE",[target]);
 return r.rows[0]??bad(404,"TARGET_NOT_FOUND");
}
const active=(target:Target):void=>{if(target.lifecycle!=="ACTIVE")bad(409,"TARGET_NOT_ACTIVE");};
const origin=(target:Target)=>new URL(target.base_url).origin;
async function audit(tx:PoolClient,t:string,target:Target,action:string,details:Record<string,unknown>={}){
 await tx.query("INSERT INTO api_target_events(id,tenant_id,target_id,action,revision,details) VALUES($1,$2,$3,$4,$5,$6::jsonb)",[uuid(),t,target.id,action,target.revision,JSON.stringify(details)]);
}
async function invalidate(tx:PoolClient,id:string){
 await tx.query("UPDATE api_target_challenges SET status='REVOKED' WHERE target_id=$1 AND status='ISSUED'",[id]);
}
const normalizeErrors=(e:unknown):never=>{if(e instanceof TargetInputError)bad(400,e.reason);throw e;};
function bound(req:FastifyRequest){return id((req.params as {id:string}).id);}
export async function registerOnboardingRoutes(app:FastifyInstance,tenant:(req:FastifyRequest)=>string) {
 app.patch("/v1/targets/:id",async req=>{
  const targetId=bound(req),b=data(req.body),t=tenant(req),revision=checkRevision(b.revision);
  if(Object.keys(b).some(k=>!["revision","name","baseUrl","environment"].includes(k)))bad(400,"INVALID_TARGET_FIELDS");
  try{return await withTenant(t,async tx=>{
   const old=await locked(tx,targetId);active(old);if(old.revision!==revision)bad(409,"STALE_TARGET_REVISION");
   const name=b.name===undefined?old.name:checkName(b.name),url=b.baseUrl===undefined?old.base_url:canonicalTargetUrl(b.baseUrl).canonicalUrl;
   const env=b.environment===undefined?old.environment:checkEnvironment(b.environment);
   const changed=url!==old.base_url||env!==old.environment;
   const r=await tx.query("UPDATE api_targets SET name=$2,base_url=$3,environment=$4,revision=revision+1,verification_version=verification_version+$5,scope_revision=scope_revision+$6,ownership_status=CASE WHEN $5=1 THEN 'PENDING_HOST_VERIFICATION' ELSE ownership_status END,updated_at=now() WHERE id=$1 RETURNING *",[targetId,name,url,env,changed?1:0,changed?1:0]);
   if(changed)await invalidate(tx,targetId);
   await audit(tx,t,r.rows[0],"TARGET_UPDATED",{scopeAndVerificationInvalidated:changed});
   return r.rows[0];
  });}catch(e){return normalizeErrors(e);}
 });
 app.post("/v1/targets/:id/lifecycle",async req=>{
  const targetId=bound(req),b=data(req.body),t=tenant(req),rev=checkRevision(b.revision);
  if(!["SUSPEND","REVOKE","ARCHIVE","RESTORE"].includes(String(b.action)))bad(400,"INVALID_LIFECYCLE_ACTION");
  return withTenant(t,async tx=>{
   const old=await locked(tx,targetId);if(old.revision!==rev)bad(409,"STALE_TARGET_REVISION");
   const graph:Record<string,Record<string,string>>={ACTIVE:{SUSPEND:"SUSPENDED",REVOKE:"REVOKED",ARCHIVE:"ARCHIVED"},SUSPENDED:{RESTORE:"ACTIVE",REVOKE:"REVOKED",ARCHIVE:"ARCHIVED"},REVOKED:{},ARCHIVED:{}};
   const next=graph[old.lifecycle]?.[String(b.action)];if(!next)bad(409,"INVALID_LIFECYCLE_TRANSITION");
   const r=await tx.query("UPDATE api_targets SET lifecycle=$2,revision=revision+1,verification_version=verification_version+1,ownership_status='PENDING_HOST_VERIFICATION',updated_at=now(),archived_at=CASE WHEN $2='ARCHIVED' THEN now() ELSE archived_at END WHERE id=$1 RETURNING *",[targetId,next]);
   await invalidate(tx,targetId);await audit(tx,t,r.rows[0],"TARGET_"+b.action,{from:old.lifecycle,to:next});
   return r.rows[0];
  });
 });
 app.post("/v1/targets/:id/scopes",async req=>{
  const targetId=bound(req),b=data(req.body),t=tenant(req),rev=checkRevision(b.revision);
  try{return await withTenant(t,async tx=>{
   const old=await locked(tx,targetId);active(old);if(old.revision!==rev)bad(409,"STALE_TARGET_REVISION");
   const proposal=checkScope(b.proposal,origin(old)),scopeId=uuid(),scopeRev=old.scope_revision+1;
   await tx.query("INSERT INTO api_target_scopes(id,tenant_id,target_id,revision,proposal) VALUES($1,$2,$3,$4,$5::jsonb)",[scopeId,t,targetId,scopeRev,JSON.stringify(proposal)]);
   const r=await tx.query("UPDATE api_targets SET revision=revision+1,scope_revision=$2,verification_version=verification_version+1,ownership_status='PENDING_HOST_VERIFICATION',updated_at=now() WHERE id=$1 RETURNING *",[targetId,scopeRev]);
   await invalidate(tx,targetId);await audit(tx,t,r.rows[0],"SCOPE_PROPOSED",{scopeRevision:scopeRev,scopeId});
   return {id:scopeId,scopeRevision:scopeRev,revision:r.rows[0].revision,authority:"CUSTOMER_PROPOSED",ownershipStatus:r.rows[0].ownership_status,proposal};
  });}catch(e){return normalizeErrors(e);}
 });
 app.get("/v1/targets/:id/scopes",async req=>withTenant(tenant(req),async tx=>{
   const targetId=bound(req);
   if(!(await tx.query("SELECT id FROM api_targets WHERE id=$1",[targetId])).rowCount)bad(404,"TARGET_NOT_FOUND");
   return (await tx.query('SELECT id,revision,proposal,authority_status AS "authorityStatus",created_at AS "createdAt" FROM api_target_scopes WHERE target_id=$1 ORDER BY revision DESC LIMIT 25',[targetId])).rows;
 }));
 app.post("/v1/targets/:id/verification/challenges",async req=>{
  const targetId=bound(req),t=tenant(req),rev=checkRevision(data(req.body).revision);
  return withTenant(t,async tx=>{
   const old=await locked(tx,targetId);active(old);if(old.revision!==rev)bad(409,"STALE_TARGET_REVISION");
   await invalidate(tx,targetId);
   const rawNonce=nonce(),challengeId=uuid(),expires=new Date(Date.now()+10*60*1000).toISOString();
   await tx.query("INSERT INTO api_target_challenges(id,tenant_id,target_id,nonce_hash,origin,environment,verification_version,target_revision,status,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,'ISSUED',$9)",
     [challengeId,t,targetId,sha256(rawNonce),origin(old),old.environment,old.verification_version,old.revision,expires]);
   await audit(tx,t,old,"VERIFICATION_CHALLENGE_ISSUED",{challengeId,expiresAt:expires});
   return {id:challengeId,targetId,challengeNonce:rawNonce,origin:origin(old),environment:old.environment,verificationVersion:old.verification_version,status:"ISSUED",expiresAt:expires,authority:"PENDING_HOST_VERIFICATION"};
  });
 });
 app.get("/v1/targets/:id/verification/challenges",async req=>withTenant(tenant(req),async tx=>{
  const targetId=bound(req);
  if(!(await tx.query("SELECT id FROM api_targets WHERE id=$1",[targetId])).rowCount)bad(404,"TARGET_NOT_FOUND");
  return (await tx.query('SELECT id,target_id AS "targetId",status,origin,environment,verification_version AS "verificationVersion",issued_at AS "issuedAt",expires_at AS "expiresAt" FROM api_target_challenges WHERE target_id=$1 ORDER BY issued_at DESC LIMIT 25',[targetId])).rows;
 }));
 app.post("/v1/targets/:id/verification/revoke",async req=>{
  const targetId=bound(req),t=tenant(req),rev=checkRevision(data(req.body).revision);
  return withTenant(t,async tx=>{
   const old=await locked(tx,targetId);if(old.revision!==rev)bad(409,"STALE_TARGET_REVISION");
   await invalidate(tx,targetId);
   const r=await tx.query("UPDATE api_targets SET revision=revision+1,verification_version=verification_version+1,ownership_status='PENDING_HOST_VERIFICATION',updated_at=now() WHERE id=$1 RETURNING *",[targetId]);
   await audit(tx,t,r.rows[0],"VERIFICATION_REVOKED");return r.rows[0];
  });
 });
 app.post("/v1/test-authority/attest",async req=>{
  try{fixtureSigningKey();}catch{bad(503,"SYNTHETIC_AUTHORITY_UNAVAILABLE");}
  const b=data(req.body),targetId=id(b.targetId),challengeId=id(b.challengeId),t=tenant(req);
  return withTenant(t,async tx=>{
   const old=await locked(tx,targetId);active(old);
   if(old.environment!=="SYNTHETIC")bad(403,"SYNTHETIC_ONLY_ENVIRONMENT");
   const ch=(await tx.query("SELECT * FROM api_target_challenges WHERE id=$1 AND target_id=$2",[challengeId,targetId])).rows[0];
   if(!ch)bad(404,"CHALLENGE_NOT_FOUND");
   if(ch.status!=="ISSUED"||new Date(ch.expires_at).getTime()<=Date.now())bad(409,"CHALLENGE_NOT_CURRENT");
   if(ch.verification_version!==old.verification_version||ch.target_revision!==old.revision)bad(409,"CHALLENGE_STALE");
   const claims:SyntheticClaims={v:1,tenant:t,target:targetId,challenge:challengeId,origin:ch.origin,environment:ch.environment,
     revision:ch.target_revision,verificationVersion:ch.verification_version,nonceHash:ch.nonce_hash,expiresAt:new Date(ch.expires_at).toISOString()};
   return {attestation:signSynthetic(claims),issuer:"SYNTHETIC_TEST_ONLY",productionAuthorization:false};
  });
 });
 app.post("/v1/targets/:id/verification/evidence",async(req,reply)=>{
  const targetId=bound(req),t=tenant(req),b=data(req.body),challengeId=id(b.challengeId),kind=b.evidenceType;
  if(kind==="HOST_ATTESTATION")bad(503,"HOST_VERIFICATION_NOT_CONFIGURED");
  if(!["CUSTOMER_CLAIM","SIGNED_SYNTHETIC_ATTESTATION"].includes(String(kind)))bad(400,"INVALID_EVIDENCE_TYPE");
  if(typeof b.attestation!=="string"||b.attestation.length<1||b.attestation.length>4096)bad(400,"INVALID_EVIDENCE");
  let claims:SyntheticClaims|null=null;
  if(kind==="SIGNED_SYNTHETIC_ATTESTATION"){
   try{claims=verifySynthetic(b.attestation);}catch(e){if(e instanceof TargetInputError)bad(403,e.reason);throw e;}
  }
  const result=await withTenant(t,async tx=>{
   const old=await locked(tx,targetId);active(old);
   const ch=(await tx.query("SELECT * FROM api_target_challenges WHERE id=$1 AND target_id=$2 FOR UPDATE",[challengeId,targetId])).rows[0];
   if(!ch)bad(404,"CHALLENGE_NOT_FOUND");
   if(ch.status!=="ISSUED")bad(409,"CHALLENGE_REPLAY_OR_REVOKED");
   if(Date.now()>=new Date(ch.expires_at).getTime()){
     await tx.query("UPDATE api_target_challenges SET status='EXPIRED' WHERE id=$1",[challengeId]);
     await audit(tx,t,old,"CHALLENGE_EXPIRED",{challengeId});
     return {status:"EXPIRED",authority:"NONE",verified:false};
   }
   if(ch.verification_version!==old.verification_version||ch.target_revision!==old.revision||ch.environment!==old.environment||ch.origin!==origin(old))bad(409,"STALE_CHALLENGE_CONTEXT");
   const accepted=!!claims && old.environment==="SYNTHETIC" && claims.v===1 && claims.tenant===t &&
     claims.target===targetId&&claims.challenge===challengeId&&claims.origin===ch.origin&&claims.environment===ch.environment&&
     claims.revision===ch.target_revision&&claims.verificationVersion===ch.verification_version&&
     claims.nonceHash===ch.nonce_hash&&claims.expiresAt===new Date(ch.expires_at).toISOString();
   if(claims&&!accepted)bad(403,"ATTESTATION_CONTEXT_MISMATCH");
   const evidenceId=uuid();
   await tx.query("INSERT INTO api_target_verification_evidence(id,tenant_id,target_id,challenge_id,evidence_type,evidence_sha256,outcome) VALUES($1,$2,$3,$4,$5,$6,$7)",
     [evidenceId,t,targetId,challengeId,kind,sha256(b.attestation as string),accepted?"ACCEPTED_SYNTHETIC":"REJECTED_UNVERIFIED"]);
   if(!accepted){await audit(tx,t,old,"VERIFICATION_CLAIM_RECEIVED",{challengeId,evidenceId});return {status:"PENDING_HOST_VERIFICATION",authority:"NONE",verified:false};}
   await tx.query("UPDATE api_target_challenges SET status='CONSUMED',consumed_at=now() WHERE id=$1",[challengeId]);
   await tx.query("INSERT INTO api_target_verification_decisions(id,tenant_id,target_id,challenge_id,evidence_id,decision,decision_authority,origin,environment,verification_version) VALUES($1,$2,$3,$4,$5,'SYNTHETIC_VERIFIED_TEST_ONLY','SYNTHETIC_TEST_ONLY',$6,$7,$8)",
     [uuid(),t,targetId,challengeId,evidenceId,ch.origin,ch.environment,ch.verification_version]);
   await tx.query("UPDATE api_targets SET ownership_status='SYNTHETIC_VERIFIED_TEST_ONLY',updated_at=now() WHERE id=$1",[targetId]);
   await audit(tx,t,old,"VERIFICATION_SYNTHETIC_ACCEPTED",{challengeId,evidenceId});
   return {status:"SYNTHETIC_VERIFIED_TEST_ONLY",authority:"SYNTHETIC_TEST_ONLY",verified:true,liveExecutionAuthorized:false,hostVerified:false};
  });
  reply.code(result.verified?200:202).send(result);
 });
 app.get("/v1/targets/:id/verification/decisions",async req=>withTenant(tenant(req),async tx=>{
  const targetId=bound(req);
  if(!(await tx.query("SELECT id FROM api_targets WHERE id=$1",[targetId])).rowCount)bad(404,"TARGET_NOT_FOUND");
  return (await tx.query('SELECT id,challenge_id AS "challengeId",decision,decision_authority AS authority,origin,environment,verification_version AS "verificationVersion",decided_at AS "decidedAt" FROM api_target_verification_decisions WHERE target_id=$1 ORDER BY decided_at DESC LIMIT 25',[targetId])).rows;
 }));
 app.post("/v1/targets/:id/credentials",async(req,reply)=>{
  const targetId=bound(req),t=tenant(req),b=data(req.body),rev=checkRevision(b.revision);
  try{const reference=checkCredentialReference(b.reference),out=await withTenant(t,async tx=>{
    const old=await locked(tx,targetId);active(old);if(old.revision!==rev)bad(409,"STALE_TARGET_REVISION");
    const refId=uuid();
    await tx.query("INSERT INTO api_target_credentials(id,tenant_id,target_id,reference,status) VALUES($1,$2,$3,$4,'UNVERIFIED_REFERENCE')",[refId,t,targetId,reference]);
    await audit(tx,t,old,"CREDENTIAL_REFERENCE_ADDED",{credentialReferenceId:refId});
    return {id:refId,reference,status:"UNVERIFIED_REFERENCE",hostAuthorized:false};
   });reply.code(201).send(out);
  }catch(e){return normalizeErrors(e);}
 });
 app.get("/v1/targets/:id/credentials",async req=>withTenant(tenant(req),async tx=>{
  const targetId=bound(req);
  if(!(await tx.query("SELECT id FROM api_targets WHERE id=$1",[targetId])).rowCount)bad(404,"TARGET_NOT_FOUND");
  return (await tx.query('SELECT id,reference,status,created_at AS "createdAt" FROM api_target_credentials WHERE target_id=$1 ORDER BY created_at DESC LIMIT 50',[targetId])).rows;
 }));
 app.delete("/v1/targets/:id/credentials/:refId",async req=>{
  const p=req.params as {id:string;refId:string},targetId=id(p.id),refId=id(p.refId),t=tenant(req);
  return withTenant(t,async tx=>{
   const old=await locked(tx,targetId);active(old);
   if(!(await tx.query("DELETE FROM api_target_credentials WHERE target_id=$1 AND id=$2 RETURNING id",[targetId,refId])).rowCount)bad(404,"CREDENTIAL_REFERENCE_NOT_FOUND");
   await audit(tx,t,old,"CREDENTIAL_REFERENCE_DELETED",{credentialReferenceId:refId});return {deleted:true};
  });
 });
 app.get("/v1/targets/:id/history",async req=>withTenant(tenant(req),async tx=>{
  const targetId=bound(req);
  if(!(await tx.query("SELECT id FROM api_targets WHERE id=$1",[targetId])).rowCount)bad(404,"TARGET_NOT_FOUND");
  return (await tx.query('SELECT id,action,revision,details,occurred_at AS "occurredAt" FROM api_target_events WHERE target_id=$1 ORDER BY occurred_at DESC,id DESC LIMIT 100',[targetId])).rows;
 }));
}
