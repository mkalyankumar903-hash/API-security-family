import { domainToASCII } from "node:url";
import { isIP } from "node:net";
import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";

export class TargetInputError extends Error {constructor(public reason:string){super(reason);}}
export type TargetEnvironment = "SYNTHETIC" | "STAGING" | "PRODUCTION";
export type TargetLifecycle = "ACTIVE" | "SUSPENDED" | "REVOKED" | "ARCHIVED";
export type ProposedScope = {origins:string[];paths:string[];exclusions:string[];methods:string[];operations:string[];maxRequests:number;windowStart:string|null;windowEnd:string|null;authority:"CUSTOMER_PROPOSED"};
const fail=(reason:string):never=>{throw new TargetInputError(reason);};
export function canonicalTargetUrl(value:unknown):{canonicalUrl:string;origin:string} {
 if(typeof value!=="string" || value.length<12 || value.length>2048 || value.trim()!==value || /%(?:2f|5c|2e|00|25)|\\/i.test(value) || [...value].some(ch=>ch.charCodeAt(0)<32||ch.charCodeAt(0)===127))fail("UNSAFE_TARGET_URL");
 let url:URL;
 try{url=new URL(value as string);}catch{return fail("INVALID_TARGET_URL");}
 if(url.protocol!=="https:" || url.username || url.password || url.search || url.hash)fail("UNSAFE_TARGET_URL");
 if(!(value as string).startsWith("https://") || /@/.test(value as string))fail("UNSAFE_TARGET_URL");
 const inputHost=(value as string).slice(8).split(/[/:?#]/)[0] ?? "";
 if(!/^[A-Za-z0-9.-]+$/.test(inputHost)|| inputHost.endsWith(".") || inputHost.startsWith(".") || inputHost.includes(".."))fail("INVALID_DNS_NAME");
 const host=domainToASCII(inputHost).toLowerCase();
 if(!host || host!==url.hostname || host.length>253 || isIP(host)!==0)fail("INVALID_DNS_NAME");
 const labels=host.split(".");
 if(labels.length<2 || labels.some(s=>s.length<1||s.length>63||!/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(s))
    || ["localhost","local","internal","lan","home","arpa"].includes(labels.at(-1)??"")
    || /^[0-9.]+$/.test(host)) fail("INVALID_DNS_NAME");
 if(url.port && !["8443","9443"].includes(url.port))fail("UNAPPROVED_PORT");
 if(url.pathname.includes("//") || url.pathname.includes("/./") || url.pathname.includes("/../"))fail("AMBIGUOUS_PATH");
 const canonicalUrl=url.origin + (url.pathname==="/"?"":url.pathname.replace(/\/$/,""));
 const suppliedPath=(value as string).slice(8+inputHost.length).replace(/^:[0-9]+/,"");
 if(suppliedPath && suppliedPath!=="/" && suppliedPath!==url.pathname && suppliedPath!==url.pathname.replace(/\/$/,""))fail("AMBIGUOUS_PATH");
 return {canonicalUrl,origin:url.origin};
}
export function checkEnvironment(value:unknown):TargetEnvironment {
 if(value!=="SYNTHETIC"&&value!=="STAGING"&&value!=="PRODUCTION")return fail("INVALID_ENVIRONMENT");
 return value;
}
export function checkName(value:unknown):string {
 if(typeof value!=="string" || value!==value.trim() || value.length<1||value.length>120)return fail("INVALID_TARGET_NAME");
 return value;
}
export function checkRevision(value:unknown):number {
 if(!Number.isSafeInteger(value) || (value as number)<1)return fail("INVALID_REVISION");
 return value as number;
}
export function checkScope(value:unknown,origin:string):ProposedScope{
 if(!value || typeof value!=="object" || Array.isArray(value))return fail("INVALID_SCOPE");
 const data=value as Record<string,unknown>,keys=["origins","paths","exclusions","methods","operations","maxRequests","windowStart","windowEnd"];
 if(Object.keys(data).some(k=>!keys.includes(k)))return fail("INVALID_SCOPE_FIELDS");
 const arr=(key:string,cap=32):string[]=>{
  const v=data[key];
  if(!Array.isArray(v)||v.length>cap||v.some(i=>typeof i!=="string"||i.length>200||!i.length)||new Set(v).size!==v.length)return fail("INVALID_SCOPE_"+key.toUpperCase());
  return v as string[];
 };
 const origins=arr("origins",4);
 if(origins.length!==1||origins[0]!==origin)return fail("SCOPE_ORIGIN_MISMATCH");
 const paths=arr("paths"),exclusions=arr("exclusions"),methods=arr("methods"),operations=arr("operations",50);
 if(!paths.length||paths.some(s=>!/^\/[A-Za-z0-9_./*-]*$/.test(s)||s.includes("..")||s.includes("//")||s.includes("**")) ||
 exclusions.some(s=>!/^\/[A-Za-z0-9_./*-]*$/.test(s)||s.includes("..")||s.includes("//")))return fail("INVALID_SCOPE_PATH");
 if(methods.some(m=>!["GET","HEAD","OPTIONS","POST","PUT","PATCH","DELETE"].includes(m)))return fail("INVALID_SCOPE_METHOD");
 if(operations.some(op=>!/^(GET|HEAD|OPTIONS|POST|PUT|PATCH|DELETE) \/[A-Za-z0-9_./{}-]*$/.test(op)))return fail("INVALID_SCOPE_OPERATION");
 if(!Number.isSafeInteger(data.maxRequests)||(data.maxRequests as number)<0||(data.maxRequests as number)>100000)return fail("INVALID_SCOPE_BUDGET");
 const parseWindow=(x:unknown):string|null=>{
  if(x===null||x===undefined)return null;
  if(typeof x!=="string"||!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(x)||!Number.isFinite(Date.parse(x)))return fail("INVALID_SCOPE_WINDOW");
  return x;
 };
 const windowStart=parseWindow(data.windowStart),windowEnd=parseWindow(data.windowEnd);
 if(Boolean(windowStart)!==Boolean(windowEnd)||(windowStart && windowEnd && Date.parse(windowEnd)<=Date.parse(windowStart)))return fail("INVALID_SCOPE_WINDOW");
 return {origins,paths,exclusions,methods,operations,maxRequests:data.maxRequests as number,windowStart,windowEnd,authority:"CUSTOMER_PROPOSED"};
}
export function checkCredentialReference(value:unknown):string {
 if(typeof value!=="string" || !/^credref:[A-Za-z0-9_-]{8,128}$/.test(value))return fail("INVALID_CREDENTIAL_REFERENCE");
 return value;
}
export const sha256=(value:string)=>createHash("sha256").update(value).digest("hex");
export const nonce=()=>randomBytes(32).toString("base64url");
export type SyntheticClaims={v:1;tenant:string;target:string;challenge:string;origin:string;environment:string;revision:number;verificationVersion:number;nonceHash:string;expiresAt:string};
export function fixtureSigningKey():Buffer {
 if(process.env.NODE_ENV==="production"||process.env.SYNTHETIC_VERIFICATION_ENABLED!=="true")return fail("SYNTHETIC_AUTHORITY_DISABLED");
 const key=process.env.PHASE1_SYNTHETIC_SIGNING_KEY;
 if(!key || key.length<32)return fail("SYNTHETIC_SIGNING_ROOT_REQUIRED");
 return Buffer.from(key,"utf8");
}
export function signSynthetic(claims:SyntheticClaims):string {
 const encoded=Buffer.from(JSON.stringify(claims),"utf8").toString("base64url");
 const signature=createHmac("sha256",fixtureSigningKey()).update(encoded).digest("base64url");
 return encoded+"."+signature;
}
export function verifySynthetic(value:unknown):SyntheticClaims {
 if(typeof value!=="string"||value.length>4096|| !/^[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$/.test(value))return fail("INVALID_ATTESTATION");
 const [encoded,signature]=value.split(".");
 // Strict Base64URL: 32-byte SHA-256 HMAC has exactly 43 canonical unpadded characters.
 // Buffer.from(base64url) accepts noncanonical final pad bits; reject encoding aliases.
 if(!signature || signature.length!==43)return fail("ATTESTATION_SIGNATURE_INVALID");
 const supplied=Buffer.from(signature,"base64url");
 if(supplied.length!==32||supplied.toString("base64url")!==signature)return fail("ATTESTATION_SIGNATURE_INVALID");
 const expected=createHmac("sha256",fixtureSigningKey()).update(encoded??"").digest();
 if(!timingSafeEqual(expected,supplied))return fail("ATTESTATION_SIGNATURE_INVALID");
 let obj:unknown;
 try{obj=JSON.parse(Buffer.from(encoded??"","base64url").toString("utf8"));}catch{return fail("INVALID_ATTESTATION");}
 const fields=["v","tenant","target","challenge","origin","environment","revision","verificationVersion","nonceHash","expiresAt"];
 if(!obj||typeof obj!=="object"||Array.isArray(obj)||Object.keys(obj).sort().join()!==fields.sort().join())return fail("INVALID_ATTESTATION_CLAIMS");
 const claims=obj as SyntheticClaims;
 if(claims.v!==1||typeof claims.expiresAt!=="string"||Date.parse(claims.expiresAt)<=Date.now())return fail("ATTESTATION_EXPIRED");
 return claims;
}
