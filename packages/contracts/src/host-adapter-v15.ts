/** Phase15 DRAFT Host boundary. This validates CI simulator ONLY; it mints no production authority. */
import {createHmac,timingSafeEqual} from "node:crypto";
export const HOST_ADAPTER_SCHEMA="api-family-host-adapter-v15-draft" as const;
export const HOST_NOT_CONFIGURED="HOST_AUTHORITY_NOT_CONFIGURED" as const;
export const CI_ISSUER="phase15-ci-only-host-simulator" as const;
export const CI_AUDIENCE="lumicsec-api-family-phase15-ci" as const;
export type HostAdapterCapability="identity"|"membership"|"ownership"|"execution-permit"|"entitlement"|"finding-projection"|"report-reference"|"retest-handoff"|"event"|"plugin-mount"|"readiness";
export const CAPABILITIES:readonly HostAdapterCapability[]=["identity","membership","ownership","execution-permit","entitlement","finding-projection","report-reference","retest-handoff","event","plugin-mount","readiness"];
export type HostAdapterEnvelope={
 schemaVersion:typeof HOST_ADAPTER_SCHEMA;issuer:string;audience:string;tenantId:string;
 organizationId:string;clientId:string|null;capability:HostAdapterCapability;
 eventId:string;sequence:number;issuedAt:number;expiresAt:number;
 permissions:string[];payload:Record<string,unknown>;signature:string;
};
export type HostContext={tenantId:string;organizationId:string;clientId:string|null;capability:HostAdapterCapability;requiredPermission:string;now?:number};
export class HostAdapterError extends Error{
 constructor(readonly code:string){super(code);}
}
export type CITrust={root:Uint8Array;seen:Set<string>;lastSequence:Map<string,number>};
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const obj=(v:unknown):v is Record<string,unknown>=>!!v&&typeof v==="object"&&!Array.isArray(v);
const reject=(code:string):never=>{throw new HostAdapterError(code);};
function canonical(value:Omit<HostAdapterEnvelope,"signature">):string{
 return JSON.stringify([value.schemaVersion,value.issuer,value.audience,value.tenantId,
  value.organizationId,value.clientId,value.capability,value.eventId,value.sequence,
  value.issuedAt,value.expiresAt,value.permissions,value.payload]);
}
/** This signer is callable only from explicit isolated GitHub CI tests; never use for production. */
export function signCISimulatorOnly(unsigned:Omit<HostAdapterEnvelope,"signature">,root:Uint8Array):HostAdapterEnvelope{
 if(process.env.NODE_ENV!=="test"||process.env.GITHUB_ACTIONS!=="true"||process.env.PHASE15_SIMULATOR_ENABLED!=="true")
  return reject(HOST_NOT_CONFIGURED);
 if(root.byteLength<32)return reject("CI_TRUST_ROOT_TOO_SHORT");
 return {...unsigned,signature:createHmac("sha256",root).update(canonical(unsigned)).digest("hex")};
}
export function verifyCISimulatorOnly(input:unknown,context:HostContext,trust?:CITrust):HostAdapterEnvelope{
 // Neither the fixture issuer nor its signing root is a production trust relationship.
 if(process.env.NODE_ENV!=="test"||process.env.GITHUB_ACTIONS!=="true"||
    process.env.PHASE15_SIMULATOR_ENABLED!=="true"||!trust)
  return reject(HOST_NOT_CONFIGURED);
 if(trust.root.byteLength<32)return reject("CI_TRUST_ROOT_TOO_SHORT");
 if(!obj(input))return reject("HOST_INVALID_ENVELOPE");
 const e=input as Record<string,unknown>;
 if(e.schemaVersion!==HOST_ADAPTER_SCHEMA)return reject("HOST_UNSUPPORTED_SCHEMA");
 if(e.issuer!==CI_ISSUER||e.audience!==CI_AUDIENCE)return reject("HOST_UNTRUSTED_ISSUER_OR_AUDIENCE");
 if(typeof e.tenantId!=="string"||!UUID.test(e.tenantId)||
    typeof e.organizationId!=="string"||!UUID.test(e.organizationId)||
    (e.clientId!==null&&(typeof e.clientId!=="string"||!UUID.test(e.clientId)))||
    typeof e.eventId!=="string"||!UUID.test(e.eventId))
  return reject("HOST_INVALID_BINDING");
 if(e.tenantId!==context.tenantId||e.organizationId!==context.organizationId||
   e.clientId!==context.clientId)return reject("HOST_TENANT_OR_ORGANIZATION_MISMATCH");
 if(!CAPABILITIES.includes(e.capability as HostAdapterCapability)||e.capability!==context.capability)
  return reject("HOST_CAPABILITY_MISMATCH");
 const now=context.now??Math.floor(Date.now()/1000);
 if(!Number.isSafeInteger(e.issuedAt)||!Number.isSafeInteger(e.expiresAt)||
    (e.issuedAt as number)>now+30||(e.expiresAt as number)<=now||
    (e.expiresAt as number)-(e.issuedAt as number)>300)return reject("HOST_EXPIRED_OR_INVALID_TIME");
 if(!Number.isSafeInteger(e.sequence)||(e.sequence as number)<1)return reject("HOST_INVALID_SEQUENCE");
 if(!Array.isArray(e.permissions)||e.permissions.length>32||
    !e.permissions.every(p=>typeof p==="string"&&p.length>0&&p.length<=100)||
    !e.permissions.includes(context.requiredPermission))return reject("HOST_PERMISSION_DENIED");
 if(!obj(e.payload)||JSON.stringify(e.payload).length>32768)return reject("HOST_INVALID_PAYLOAD");
 if(e.payload.verifiedFixed===true||e.payload.status==="VERIFIED_FIXED"||e.payload.scanningAuthority===true)
  return reject("HOST_CANONICAL_AUTHORITY_FORBIDDEN");
 if(typeof e.signature!=="string"||!/^[a-f0-9]{64}$/i.test(e.signature))return reject("HOST_INVALID_SIGNATURE");
 const {signature,...unsigned}=e;
 const expected=createHmac("sha256",trust.root).update(canonical(unsigned as Omit<HostAdapterEnvelope,"signature">)).digest();
 const given=Buffer.from(signature,"hex");
 if(given.length!==expected.length||!timingSafeEqual(given,expected))return reject("HOST_INVALID_SIGNATURE");
 const key=e.issuer+":"+e.tenantId+":"+e.eventId;
 const sequenceKey=e.issuer+":"+e.tenantId+":"+e.capability;
 if(trust.seen.has(key))return reject("HOST_REPLAYED_EVENT");
 if((trust.lastSequence.get(sequenceKey)??0)>=(e.sequence as number))return reject("HOST_OUT_OF_ORDER_EVENT");
 // Consume nonce only after authenticating ALL bindings; no cross-tenant poison.
 trust.seen.add(key);trust.lastSequence.set(sequenceKey,e.sequence as number);
 return e as HostAdapterEnvelope;
}
/** Adapter integration failure has no allow/safe fallback. */
export function hostTransportFailure(status?:number):never{
 if(status===401||status===403)return reject("HOST_AUTHENTICATION_DENIED");
 if(status===409)return reject("HOST_REVISION_CONFLICT");
 if(status===429)return reject("HOST_RATE_LIMITED");
 return reject("HOST_UNAVAILABLE");
}
export function requireProductionHost():never{return reject(HOST_NOT_CONFIGURED);}
