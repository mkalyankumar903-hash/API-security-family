/** Isolated v13 contracts. Nothing here mints a production Host identity. */
import {createHash,createHmac,timingSafeEqual} from "node:crypto";
export const V13="api-family-commercial-v13" as const;
export const features=["IMMUTABLE_REPORT_OBSERVED"] as const;
export type Feature=typeof features[number];
export type HostIdentityAdapter={resolveIdentity(token:string):Promise<{tenantId:string;subject:string;issuer:string}|null>};
export type HostEntitlementAdapter={verifyEntitlement(raw:Uint8Array):Promise<VerifiedEntitlement>};
export type HostCommercialEventAdapter={verifyEvent(raw:Uint8Array,signature:string):Promise<CommercialEvent>};
export type HostUsageReconciliationAdapter={verifySnapshot(raw:Uint8Array):Promise<unknown>};
export type HostTenantContextAdapter={authorize(tenantId:string,subject:string,feature:Feature):Promise<boolean>};
export type VerifiedEntitlement={tenantId:string;entitlementId:string;feature:Feature;revision:number;limit:number;status:"ISSUED"|"REVOKED";issuer:string;audience:string};
export type CommercialEvent={schemaVersion:typeof V13;eventId:string;tenantId:string;issuer:string;audience:string;issuedAt:string;expiresAt:string;entitlementId:string;revision:number;feature:Feature;limit:number;status:"ISSUED"|"REVOKED"};
export type DecisionCode="ALLOWED"|"HOST_AUTHORITY_NOT_CONFIGURED"|"ENTITLEMENT_MISSING"|"ENTITLEMENT_REVOKED"|"ENTITLEMENT_EXPIRED"|"QUOTA_EXCEEDED"|"INVALID_QUANTITY"|"UNSUPPORTED_CONTRACT";
export class CommercialContractError extends Error{constructor(readonly code:string){super(code);}}
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const fields=["schemaVersion","eventId","tenantId","issuer","audience","issuedAt","expiresAt","entitlementId","revision","feature","limit","status"];
export function unit(value:unknown,max=1000000):number{
 if(typeof value!=="number"||!Number.isSafeInteger(value)||value<0||value>max)throw new CommercialContractError("INVALID_QUANTITY");
 return value;
}
export function validateEvent(value:unknown,now=Date.now()):CommercialEvent{
 if(!value||typeof value!=="object"||Array.isArray(value))throw new CommercialContractError("INVALID_EVENT");
 const e=value as Record<string,unknown>;
 if(Object.keys(e).length!==fields.length||Object.keys(e).some(k=>!fields.includes(k)))
  throw new CommercialContractError("UNSUPPORTED_CONTRACT");
 if(e.schemaVersion!==V13||e.issuer!=="lumicsec-ci-synthetic-v13"||e.audience!=="api-family-v13-test")
  throw new CommercialContractError("UNSUPPORTED_CONTRACT");
 for(const key of ["eventId","tenantId","entitlementId"])
  if(typeof e[key]!=="string"||!UUID.test(e[key]))throw new CommercialContractError("INVALID_BINDING");
 if(typeof e.issuedAt!=="string"||typeof e.expiresAt!=="string"||!/^\d{4}-/.test(e.issuedAt)||!/^\d{4}-/.test(e.expiresAt))
  throw new CommercialContractError("INVALID_EVENT_TIME");
 const issued=Date.parse(e.issuedAt),expires=Date.parse(e.expiresAt);
 if(!Number.isFinite(issued)||!Number.isFinite(expires)||expires<=issued||now-issued>300000||issued-now>30000||expires<=now)
  throw new CommercialContractError("EVENT_EXPIRED_OR_SKEWED");
 if(e.feature!=="IMMUTABLE_REPORT_OBSERVED"||!["ISSUED","REVOKED"].includes(String(e.status))||
  typeof e.revision!=="number"||!Number.isSafeInteger(e.revision)||e.revision<1||e.revision>1000000)
  throw new CommercialContractError("INVALID_ENTITLEMENT_EVENT");
 unit(e.limit);
 if(e.status==="ISSUED"&&e.limit===0)throw new CommercialContractError("INVALID_QUANTITY");
 return e as unknown as CommercialEvent;
}
/** Exact raw UTF-8 bytes, hex HMAC-SHA256, constant-time comparison; never reserialize before verification. */
export function verifySyntheticEvent(raw:Uint8Array,signature:string,key:Uint8Array,now=Date.now()):CommercialEvent{
 if(process.env.NODE_ENV!=="test"||process.env.SYNTHETIC_AUTH_ENABLED!=="true")
  throw new CommercialContractError("HOST_AUTHORITY_NOT_CONFIGURED");
 if(key.length<32||raw.byteLength>4096||!/^([0-9a-f]{64})$/.test(signature))
  throw new CommercialContractError("INVALID_EVENT_SIGNATURE");
 const mac=createHmac("sha256",key).update(raw).digest();
 if(!timingSafeEqual(mac,Buffer.from(signature,"hex")))throw new CommercialContractError("INVALID_EVENT_SIGNATURE");
 let parsed:unknown;
 try{parsed=JSON.parse(Buffer.from(raw).toString("utf8")) as unknown;}catch{throw new CommercialContractError("INVALID_EVENT");}
 return validateEvent(parsed,now);
}
export function fingerprint(raw:Uint8Array|string):string{return createHash("sha256").update(raw).digest("hex");}
export function hostNotConfigured():never{throw new CommercialContractError("HOST_AUTHORITY_NOT_CONFIGURED");}

/** Signing key rotation is explicit, bounded and restricted to CI synthetic trust. */
export type SyntheticKey={keyId:string;key:Uint8Array;validFrom:number;validUntil:number};
export function verifyRotatedSyntheticEvent(raw:Uint8Array,signature:string,keyId:string,keys:readonly SyntheticKey[],now=Date.now()){
 if(!/^[a-z0-9_-]{1,32}$/.test(keyId)||keys.length<1||keys.length>5)throw new CommercialContractError("UNTRUSTED_SIGNING_KEY");
 const matching=keys.filter(k=>k.keyId===keyId&&k.validFrom<=now&&k.validUntil>now);
 if(matching.length!==1)throw new CommercialContractError("UNTRUSTED_SIGNING_KEY");
 return verifySyntheticEvent(raw,signature,matching[0].key,now);
}
export type SyntheticExternalSnapshot={schemaVersion:typeof V13;snapshotId:string;
 tenantId:string;issuer:"lumicsec-ci-external-accounting-v13";
 audience:"api-family-reconcile-v13-test";feature:Feature;meterVersion:1;
 monthStart:string;watermarkAt:string;observedUnits:number;revision:number;
 issuedAt:string;expiresAt:string};
const externalFields=["schemaVersion","snapshotId","tenantId","issuer","audience","feature","meterVersion",
 "monthStart","watermarkAt","observedUnits","revision","issuedAt","expiresAt"];
/** Separate CI-only trust domain. An external accounting snapshot is never derived from local usage. */
export function verifySyntheticExternalSnapshot(raw:Uint8Array,signature:string,key:Uint8Array,now=Date.now()):SyntheticExternalSnapshot{
 if(process.env.NODE_ENV!=="test"||process.env.SYNTHETIC_AUTH_ENABLED!=="true")
  throw new CommercialContractError("HOST_AUTHORITY_NOT_CONFIGURED");
 if(raw.byteLength>4096||key.byteLength<32||!/^([0-9a-f]{64})$/.test(signature))
  throw new CommercialContractError("INVALID_SNAPSHOT_SIGNATURE");
 const mac=createHmac("sha256",key).update(raw).digest();
 if(!timingSafeEqual(mac,Buffer.from(signature,"hex")))throw new CommercialContractError("INVALID_SNAPSHOT_SIGNATURE");
 let parsed:unknown;
 try{parsed=JSON.parse(Buffer.from(raw).toString("utf8")) as unknown;}catch{throw new CommercialContractError("INVALID_SNAPSHOT");}
 if(!parsed||typeof parsed!=="object"||Array.isArray(parsed))throw new CommercialContractError("INVALID_SNAPSHOT");
 const e=parsed as Record<string,unknown>;
 if(Object.keys(e).length!==externalFields.length||Object.keys(e).some(k=>!externalFields.includes(k))||
  e.schemaVersion!==V13||e.issuer!=="lumicsec-ci-external-accounting-v13"||
  e.audience!=="api-family-reconcile-v13-test"||e.feature!==features[0]||e.meterVersion!==1)
  throw new CommercialContractError("UNSUPPORTED_CONTRACT");
 if(typeof e.snapshotId!=="string"||!UUID.test(e.snapshotId)||typeof e.tenantId!=="string"||!UUID.test(e.tenantId))
  throw new CommercialContractError("INVALID_BINDING");
 if(typeof e.monthStart!=="string"||!/^[0-9]{4}-(0[1-9]|1[0-2])-01$/.test(e.monthStart)||
  typeof e.watermarkAt!=="string"||typeof e.issuedAt!=="string"||typeof e.expiresAt!=="string")
  throw new CommercialContractError("INVALID_SNAPSHOT_PERIOD");
 const issued=Date.parse(e.issuedAt),expires=Date.parse(e.expiresAt),watermark=Date.parse(e.watermarkAt),
  start=Date.parse(e.monthStart+"T00:00:00Z");
 if(!Number.isFinite(issued)||!Number.isFinite(expires)||!Number.isFinite(watermark)||!Number.isFinite(start)||
  now-issued>300000||issued-now>30000||expires<=now||watermark<start||watermark>now+30000||
  watermark>=Date.parse(new Date(start).toISOString().slice(0,7)+"-01T00:00:00Z")+32*86400000)
  throw new CommercialContractError("INVALID_SNAPSHOT_PERIOD");
 unit(e.observedUnits,1000000000);
 if(typeof e.revision!=="number"||!Number.isSafeInteger(e.revision)||e.revision<1||e.revision>1000000)
  throw new CommercialContractError("INVALID_SNAPSHOT_REVISION");
 return e as unknown as SyntheticExternalSnapshot;
}
