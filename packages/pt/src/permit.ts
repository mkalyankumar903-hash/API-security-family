import {createHash,createHmac,randomBytes,timingSafeEqual} from "node:crypto";

/** Never accepted outside isolated test process; not a Host production permit. */
export const PT_ISSUER="lumicsec-phase06-test-authority-v1";
export const PT_AUDIENCE="lumicsec-in-process-fixture-only-v1";
export const PT_PROFILE="SYNTHETIC_PT_READ_ONLY";
export type PtClaims={
 v:1;permitId:string;issuer:string;audience:string;tenantId:string;targetId:string;
 environment:"SYNTHETIC";fixtureId:"billing-safe-v1";specificationId:string;
 specificationVersion:number;specFingerprint:string;targetVerificationVersion:number;
 targetScopeRevision:number;scopeId:string;operationKeys:string[];methods:("GET"|"HEAD")[];
 exclusions:string[];maxEvaluations:number;maxConcurrency:number;ratePerMinute:number;
 deadlineMs:number;notBefore:number;expiresAt:number;nonce:string;profile:typeof PT_PROFILE;
};
export class PermitError extends Error {
 constructor(public code:string){super(code);}
}
export const digest=(value:string)=>createHash("sha256").update(value).digest("hex");
function root():string {
 if(process.env.NODE_ENV==="production"||process.env.PT_TEST_AUTHORITY_ENABLED!=="true")
  throw new PermitError("PRODUCTION_SYNTHETIC_AUTHORIZATION_BLOCKED");
 const secret=process.env.PT_TEST_SIGNING_KEY??"";
 if(secret.length<48)throw new PermitError("TEST_SIGNING_KEY_NOT_CONFIGURED");
 return secret;
}
function b64(x:Buffer|string):string{return Buffer.from(x).toString("base64url");}
function decodeCanonical(x:string):Buffer{
 if(!/^[A-Za-z0-9_-]+$/.test(x))throw new PermitError("NONCANONICAL_PERMIT");
 const decoded=Buffer.from(x,"base64url");
 if(b64(decoded)!==x)throw new PermitError("NONCANONICAL_PERMIT");
 return decoded;
}
export function issueTestPermit(input:Omit<PtClaims,"v"|"issuer"|"audience"|"profile"|"nonce">):string{
 const key=root(),claims:PtClaims={
  v:1,issuer:PT_ISSUER,audience:PT_AUDIENCE,profile:PT_PROFILE,nonce:b64(randomBytes(24)),...input
 };
 // PostgreSQL jsonb sorts object members. Reconstruct the exact v1 issuer
 // serialization order before verifying its original keyed fingerprint.
 const fields=["v","issuer","audience","profile","nonce","permitId","tenantId",
  "targetId","environment","fixtureId","specificationId","specificationVersion",
  "specFingerprint","targetVerificationVersion","targetScopeRevision","scopeId",
  "operationKeys","methods","exclusions","maxEvaluations","maxConcurrency",
  "ratePerMinute","deadlineMs","notBefore","expiresAt"];
 const raw=claims as unknown as Record<string,unknown>;
 if(Object.keys(raw).length!==fields.length||fields.some(k=>!Object.hasOwn(raw,k)))
  throw new PermitError("PERMIT_INTEGRITY_MISMATCH");
 const ordered=Object.fromEntries(fields.map(k=>[k,raw[k]]));
 const body=b64(JSON.stringify(ordered));
 const signature=createHmac("sha256",key).update("pt6v1."+body).digest();
 return "pt6v1."+body+"."+b64(signature);
}
export function verifyTestPermit(token:string,now=Date.now()):PtClaims {
 const key=root();
 const parts=token.split(".");
 if(parts.length!==3||parts[0]!=="pt6v1")throw new PermitError("PERMIT_ALGORITHM_DENIED");
 const body=decodeCanonical(parts[1]??"");
 const signature=decodeCanonical(parts[2]??"");
 if(signature.length!==32)throw new PermitError("PERMIT_SIGNATURE_LENGTH");
 const expected=createHmac("sha256",key).update("pt6v1."+parts[1]).digest();
 if(!timingSafeEqual(signature,expected))throw new PermitError("PERMIT_SIGNATURE_INVALID");
 let c:PtClaims;
 try {c=JSON.parse(body.toString("utf8")) as PtClaims;}catch{throw new PermitError("PERMIT_JSON_INVALID");}
 if(b64(JSON.stringify(c))!==parts[1])throw new PermitError("NONCANONICAL_PERMIT");
 if(c.v!==1||c.issuer!==PT_ISSUER)throw new PermitError("PERMIT_ISSUER_DENIED");
 if(c.audience!==PT_AUDIENCE||c.profile!==PT_PROFILE||c.environment!=="SYNTHETIC"||c.fixtureId!=="billing-safe-v1")throw new PermitError("PERMIT_AUDIENCE_DENIED");
 if(!Number.isSafeInteger(c.notBefore)||!Number.isSafeInteger(c.expiresAt)||c.notBefore>now||c.expiresAt<=now||c.expiresAt-c.notBefore>15*60000)
  throw new PermitError("PERMIT_EXPIRED_OR_NOT_YET_VALID");
 if(!Array.isArray(c.operationKeys)||c.operationKeys.length===0||c.operationKeys.length>20||
  !Array.isArray(c.methods)||!c.methods.every(m=>m==="GET"||m==="HEAD")||
  !Array.isArray(c.exclusions)||!Number.isSafeInteger(c.maxEvaluations)||c.maxEvaluations<1||c.maxEvaluations>30||
  !Number.isSafeInteger(c.maxConcurrency)||c.maxConcurrency<1||c.maxConcurrency>2||
  !Number.isSafeInteger(c.ratePerMinute)||c.ratePerMinute<1||c.ratePerMinute>20)
  throw new PermitError("PERMIT_CLAIMS_INVALID");
 return c;
}
/** Independently authenticate persisted permit claims without storing a bearer
 * or signature. Only the isolated testing key can re-derive the original MAC. */
export function verifyStoredTestPermit(claims:PtClaims,tokenHash:string,now=Date.now()):PtClaims {
 const key=root();
 if(!claims||typeof claims!=="object"||Array.isArray(claims)||
  typeof tokenHash!=="string"||!/^[0-9a-f]{64}$/.test(tokenHash))
  throw new PermitError("PERMIT_INTEGRITY_MISMATCH");
 const body=b64(JSON.stringify(claims));
 const signature=createHmac("sha256",key).update("pt6v1."+body).digest();
 const reconstructed="pt6v1."+body+"."+b64(signature);
 if(!timingSafeEqual(Buffer.from(digest(reconstructed),"hex"),Buffer.from(tokenHash,"hex")))
  throw new PermitError("PERMIT_INTEGRITY_MISMATCH");
 return verifyTestPermit(reconstructed,now);
}
export function enforcePermit(c:PtClaims,context:{
 tenantId:string;targetId:string;scopeId:string;specificationId:string;specFingerprint:string;
 specificationVersion:number;targetVerificationVersion:number;targetScopeRevision:number;fixtureId:string;
 operationKey?:string;method?:string;path?:string;
}):void{
 if(c.tenantId!==context.tenantId)throw new PermitError("PERMIT_TENANT_MISMATCH");
 if(c.targetId!==context.targetId)throw new PermitError("PERMIT_TARGET_MISMATCH");
 if(c.scopeId!==context.scopeId)throw new PermitError("PERMIT_SCOPE_MISMATCH");
 if(c.specificationId!==context.specificationId||c.specificationVersion!==context.specificationVersion||
  c.specFingerprint!==context.specFingerprint)throw new PermitError("PERMIT_SPECIFICATION_MISMATCH");
 if(c.targetVerificationVersion!==context.targetVerificationVersion||c.targetScopeRevision!==context.targetScopeRevision)
  throw new PermitError("PERMIT_TARGET_REVISION_STALE");
 if(c.fixtureId!==context.fixtureId)throw new PermitError("PERMIT_FIXTURE_MISMATCH");
 if(context.operationKey&&!c.operationKeys.includes(context.operationKey))throw new PermitError("OPERATION_OUT_OF_SCOPE");
 if(context.method&&!(context.method==="GET"||context.method==="HEAD")||context.method&&!c.methods.includes(context.method as "GET"|"HEAD"))
  throw new PermitError("METHOD_DENIED");
 if(context.path&&c.exclusions.includes(context.path))throw new PermitError("PATH_EXCLUDED");
}
export function validateTestAuthority(header:unknown):void{
 const key=root(),admin=process.env.PT_TEST_AUTHORITY_KEY??"";
 if(key.length<48||admin.length<48||typeof header!=="string")
  throw new PermitError("TEST_AUTHORITY_REQUIRED");
 const supplied=Buffer.from(header),trusted=Buffer.from(admin);
 if(supplied.length!==trusted.length||!timingSafeEqual(supplied,trusted))throw new PermitError("TEST_AUTHORITY_REQUIRED");
}
