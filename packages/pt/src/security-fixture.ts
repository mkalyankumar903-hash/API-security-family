import Fastify from "fastify";
import {createHash} from "node:crypto";

/** In-process synthetic fixture. This module has no listening socket and no external fetch. */
export const DETECTION_ENGINE="pt-detection-v1" as const;
export const DETECTION_FIXTURE="pt-security-v1" as const;
export const DETECTION_FIXTURE_REVISION=1 as const;
export const PROFILES=[
 "SECURE_BASELINE","MISSING_AUTH_ENFORCEMENT","CROSS_USER_ACCESS_WEAKNESS",
 "ROLE_RESTRICTION_WEAKNESS","SENSITIVE_RESPONSE_EXPOSURE","INSECURE_CACHE_POLICY"
] as const;
export type Profile=typeof PROFILES[number];
export const ACTORS=["anonymous","alice","bob","admin","invalid","expired","revoked"] as const;
export type Actor=typeof ACTORS[number];
export const PATHS=["/pt/account","/pt/resources/bob","/pt/admin","/pt/confidential"] as const;
export type DetectionPath=typeof PATHS[number];
export type Evidence={
 status:number;method:"GET"|"HEAD";path:DetectionPath;actor:Actor;
 profile:Profile;responseHash:string;responseBytes:number;exposedPaths:string[];
 cacheControl:string|null;outcome:"FIXTURE_RESPONSE";fixtureVersion:1;
};
export function isProfile(s:unknown):s is Profile{return typeof s==="string"&&(PROFILES as readonly string[]).includes(s);}
export function isActor(s:unknown):s is Actor{return typeof s==="string"&&(ACTORS as readonly string[]).includes(s);}
export function isDetectionPath(s:unknown):s is DetectionPath{return typeof s==="string"&&(PATHS as readonly string[]).includes(s);}
export function fixtureOperationV7(method:string,path:string):boolean{
 return (method==="GET"||method==="HEAD")&&isDetectionPath(path);
}
function admitted(actor:Actor):boolean{return actor==="alice"||actor==="bob"||actor==="admin";}
const app=Fastify({logger:false,bodyLimit:1024,trustProxy:false});
const actorOf=(header:unknown):Actor=>isActor(header)?header:"anonymous";
const profileOf=(header:unknown):Profile=>isProfile(header)?header:"SECURE_BASELINE";
app.get("/pt/account",async(req,reply)=>{
 const a=actorOf(req.headers["x-trusted-synthetic-actor"]),p=profileOf(req.headers["x-trusted-synthetic-profile"]);
 if(!admitted(a)&&p!=="MISSING_AUTH_ENFORCEMENT")return reply.code(401).send({error:"UNAUTHORIZED"});
 return {resource:"synthetic-account",visible:true};
});
app.get("/pt/resources/bob",async(req,reply)=>{
 const a=actorOf(req.headers["x-trusted-synthetic-actor"]),p=profileOf(req.headers["x-trusted-synthetic-profile"]);
 if(!admitted(a))return reply.code(401).send({error:"UNAUTHORIZED"});
 if(a!=="bob"&&a!=="admin"&&p!=="CROSS_USER_ACCESS_WEAKNESS")return reply.code(403).send({error:"FORBIDDEN"});
 return {resource:"bob-synthetic-resource",owner:"bob"};
});
app.get("/pt/admin",async(req,reply)=>{
 const a=actorOf(req.headers["x-trusted-synthetic-actor"]),p=profileOf(req.headers["x-trusted-synthetic-profile"]);
 if(!admitted(a))return reply.code(401).send({error:"UNAUTHORIZED"});
 if(a!=="admin"&&p!=="ROLE_RESTRICTION_WEAKNESS")return reply.code(403).send({error:"FORBIDDEN"});
 return {operation:"synthetic-admin-read",role:"admin"};
});
app.get("/pt/confidential",async(req,reply)=>{
 const a=actorOf(req.headers["x-trusted-synthetic-actor"]),p=profileOf(req.headers["x-trusted-synthetic-profile"]);
 if(!admitted(a))return reply.code(401).send({error:"UNAUTHORIZED"});
 reply.header("cache-control",p==="INSECURE_CACHE_POLICY"?"public, max-age=3600":"private, no-store");
 return p==="SENSITIVE_RESPONSE_EXPOSURE"?
  {account:"synthetic",internalAccessToken:"SYNTHETIC_PLACEHOLDER_NOT_A_SECRET"}:
  {account:"synthetic"};
});
/** Called only by the private worker after signed-permit/governor admission.
 * The deliberately synthetic bodies never leave this module; responses persist as redacted metadata. */
export async function executeTrustedSynthetic(input:{
 method:"GET"|"HEAD";path:DetectionPath;actor:Actor;profile:Profile;
}):Promise<Evidence>{
 if(process.env.NODE_ENV==="production"||process.env.PT_TEST_AUTHORITY_ENABLED!=="true")
  throw new Error("PRODUCTION_SYNTHETIC_DETECTION_BLOCKED");
 if(!fixtureOperationV7(input.method,input.path)||!isActor(input.actor)||!isProfile(input.profile))
  throw new Error("UNTRUSTED_FIXTURE_SELECTION");
 const result=await app.inject({method:input.method,url:input.path,headers:{
  "x-trusted-synthetic-actor":input.actor,"x-trusted-synthetic-profile":input.profile
 }});
 const data=Buffer.from(result.rawPayload);
 if(data.length>2048)throw new Error("FIXTURE_RESPONSE_TOO_LARGE");
 let obj:Record<string,unknown>={};
 if(input.method==="GET"&&data.length){
  try{const decoded:unknown=JSON.parse(data.toString("utf8"));if(decoded&&typeof decoded==="object"&&!Array.isArray(decoded))obj=decoded as Record<string,unknown>;}
  catch{throw new Error("UNEXPECTED_FIXTURE_RESPONSE");}
 }
 const exposedPaths=Object.keys(obj).filter(x=>["account","internalAccessToken","resource","owner","role","visible","operation","error"].includes(x))
  .map(x=>"$."+x).sort();
 // Fingerprint redacted field names/status only; never hash or store a secret-bearing raw body.
 const fingerprintData=JSON.stringify({status:result.statusCode,paths:exposedPaths,cache:result.headers["cache-control"]??null});
 return {
  status:result.statusCode,method:input.method,path:input.path,actor:input.actor,profile:input.profile,
  responseBytes:data.length,responseHash:createHash("sha256").update(fingerprintData).digest("hex"),
  exposedPaths,cacheControl:typeof result.headers["cache-control"]==="string"?result.headers["cache-control"]:null,
  outcome:"FIXTURE_RESPONSE",fixtureVersion:1
 };
}
