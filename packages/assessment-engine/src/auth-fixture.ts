import Fastify from "fastify";
import {createHash, randomBytes, timingSafeEqual} from "node:crypto";

/**
 * Closed, allowlisted, in-memory *synthetic* application. No .listen(), fetch(),
 * DNS, shell, customer host, imported spec route, or user-supplied code.
 * Fixture identities and expected policy are source-controlled, not client claims.
 */
export const AUTH_ENGINE_VERSION = "auth-fixture-v1" as const;
export const AUTH_PROFILE = "SYNTHETIC_AUTH_FIXTURE" as const;
export const FIXTURES = ["secure-v1","broken-bola-v1"] as const;
export const SCHEMES = ["BEARER","API_KEY","BASIC","OAUTH2","SESSION"] as const;
export type Scheme = typeof SCHEMES[number];
export type Fixture = typeof FIXTURES[number];
export type Identity = "user-a" | "user-b" | "manager" | "admin";
export type FixtureRole = "reader" | "privileged" | "administrator";
export const IDENTITIES:Readonly<Record<Identity,{role:FixtureRole;owner:string}>> = Object.freeze({
 "user-a":{role:"reader",owner:"user-a"},
 "user-b":{role:"reader",owner:"user-b"},
 manager:{role:"privileged",owner:"manager"},
 admin:{role:"administrator",owner:"admin"}
});
export const FIXTURE_OPERATIONS = Object.freeze([
 {key:"FIXTURE_RECORD_A",method:"GET",path:"/fixture/records/user-a",policy:"Owner or administrator"},
 {key:"FIXTURE_RECORD_B",method:"GET",path:"/fixture/records/user-b",policy:"Owner or administrator"},
 {key:"FIXTURE_ADMIN",method:"POST",path:"/fixture/admin",policy:"Administrator only"},
 {key:"FIXTURE_SELF",method:"GET",path:"/fixture/me",policy:"Authenticated identity"}
]);
const sha=(s:string)=>createHash("sha256").update(s).digest("hex");
const newSecret=()=>randomBytes(32).toString("base64url");
const constantEqual=(a:string,b:string)=>{const x=Buffer.from(a),y=Buffer.from(b);return x.length===y.length&&timingSafeEqual(x,y);};
type Token={identity:Identity;secret:string;expiresAt:number;revoked:boolean;issuer:string;audience:string;scheme:Scheme};
export type Evaluation={
 ruleId:string;revision:"1";identity:string;role:string;operationKey:string;
 expected:"ALLOW"|"DENY";observed:"ALLOW"|"DENY"|"UNKNOWN";
 status:number;responseBytes:number;result:"PASS"|"DEVIATION"|"UNKNOWN"|"SKIPPED";
 reason:string;fingerprint:string;fixtureOnly:true;confidence:"HIGH"|"LOW";
};
export type FixtureOutput={
 fixtureVersion:Fixture;engineVersion:typeof AUTH_ENGINE_VERSION;scheme:Scheme;
 evaluations:Evaluation[];coverage:{attempted:number;passed:number;deviations:number;unknown:number;skipped:number};
 limitations:string[];runtimeValidation:false;customerNetworkRequests:0;
};
export class FixtureConfigError extends Error {constructor(public code:string){super(code);}}
function assertConfig(scheme:unknown,fixture:unknown,tenantId:unknown,targetId:unknown):asserts scheme is Scheme {
 if(!SCHEMES.includes(scheme as Scheme)||!FIXTURES.includes(fixture as Fixture))throw new FixtureConfigError("UNSUPPORTED_FIXTURE_PROFILE");
 if(typeof tenantId!=="string"||typeof targetId!=="string"||!/^[-0-9a-f]{36}$/i.test(tenantId)||!/^[-0-9a-f]{36}$/i.test(targetId))throw new FixtureConfigError("INVALID_FIXTURE_CONTEXT");
}
function expected(identity:Identity|null,operation:string):"ALLOW"|"DENY" {
 if(!identity)return "DENY";
 if(operation==="FIXTURE_SELF")return "ALLOW";
 if(operation==="FIXTURE_ADMIN")return identity==="admin"?"ALLOW":"DENY";
 if(operation==="FIXTURE_RECORD_A")return identity==="user-a"||identity==="admin"?"ALLOW":"DENY";
 if(operation==="FIXTURE_RECORD_B")return identity==="user-b"||identity==="admin"?"ALLOW":"DENY";
 return "DENY";
}
export function policyFor(identity:Identity|null,operationKey:string){return expected(identity,operationKey);}
export function declaredSchemeCoverage(schemes:Record<string,{type:string;scheme?:string;in?:string}>){
 return Object.entries(schemes).map(([name,s])=>{
  const v=s.scheme?.toLowerCase(),t=s.type?.toLowerCase();
  const mapped=t==="http"&&v==="bearer"?"BEARER":t==="http"&&v==="basic"?"BASIC":
   t==="apikey"&&s.in==="header"?"API_KEY":t==="oauth2"?"OAUTH2":null;
  return {name,declaredType:s.type,fixtureScheme:mapped,productionAuthenticated:false,
   status:mapped?"SYNTHETIC_SCHEME_AVAILABLE":"UNSUPPORTED",reason:mapped?null:"NO_TRUSTED_FIXTURE_SCHEME"};
 });
}
export async function evaluateAuthFixture(input:{
 scheme:Scheme;fixture:Fixture;tenantId:string;targetId:string;deadlineMs?:number;maxEvaluations?:number;
}):Promise<FixtureOutput>{
 const {scheme,fixture,tenantId,targetId}=input;
 assertConfig(scheme,fixture,tenantId,targetId);
 const max=input.maxEvaluations??60;
 if(!Number.isInteger(max)||max<1||max>100)throw new FixtureConfigError("INVALID_EVALUATION_LIMIT");
 const deadline=Date.now()+Math.min(10000,Math.max(100,input.deadlineMs??5000));
 const tokens=new Map<string,Token>();
 let rotations=0;
 const issuer="fixture:lumicsec-auth-v1";
 const audience=sha(tenantId+":"+targetId).slice(0,32);
 const app=Fastify({logger:false,bodyLimit:1024,maxParamLength:64});
 const issue=(identity:Identity,overrides:Partial<Pick<Token,"expiresAt"|"revoked"|"issuer"|"audience">>={})=>{
  const secret=newSecret();
  const item:Token={identity,scheme,secret,expiresAt:Date.now()+60000,revoked:false,issuer,audience,...overrides};
  tokens.set(sha(secret),item);
  return secret;
 };
 const revoke=(secret:string)=>{const t=tokens.get(sha(secret));if(t)t.revoked=true;};
 const rotate=(secret:string,identity:Identity)=>{revoke(secret);rotations++;return issue(identity);};
 function authentication(headers:Record<string,unknown>):Identity|null{
  let secret="";
  if(scheme==="BEARER"||scheme==="OAUTH2"){
   const h=headers.authorization;if(typeof h!=="string"||!h.startsWith("Bearer "))return null;secret=h.slice(7);
  }else if(scheme==="API_KEY"){
   if(typeof headers["x-fixture-api-key"]!=="string")return null;secret=headers["x-fixture-api-key"] as string;
  }else if(scheme==="SESSION"){
   const cookie=headers.cookie;if(typeof cookie!=="string")return null;
   const match=/^fixture_session=([A-Za-z0-9_-]{20,120})$/.exec(cookie);if(!match)return null;secret=match[1]??"";
  }else {
   const h=headers.authorization;if(typeof h!=="string"||!h.startsWith("Basic "))return null;
   const raw=h.slice(6);
   if(!/^[A-Za-z0-9+/=]{8,240}$/.test(raw))return null;
   const pair=Buffer.from(raw,"base64").toString("utf8").split(":");
   if(pair.length!==2||pair[0]!=="synthetic")return null;secret=pair[1]??"";
  }
  const record=tokens.get(sha(secret));
  if(!record||!constantEqual(record.secret,secret)||record.scheme!==scheme||record.revoked||
     record.expiresAt<=Date.now()||record.issuer!==issuer||record.audience!==audience)return null;
  return record.identity;
 }
 // Source-controlled method+path allowlist. Client input is never a fixture URL.
 app.get("/fixture/records/:owner",async(req,reply)=>{
  const identity=authentication(req.headers);
  if(!identity)return reply.code(401).send({error:"UNAUTHENTICATED"});
  const owner=(req.params as {owner:string}).owner;
  if(!["user-a","user-b"].includes(owner))return reply.code(404).send({error:"NOT_FOUND"});
  const permitted=identity==="admin"||IDENTITIES[identity].owner===owner||
   (fixture==="broken-bola-v1"&&identity==="user-b"&&owner==="user-a");
  return permitted?reply.code(200).send({record:"synthetic",owner}):reply.code(403).send({error:"FORBIDDEN"});
 });
 app.post("/fixture/admin",async(req,reply)=>{
  const identity=authentication(req.headers);
  return !identity?reply.code(401).send({error:"UNAUTHENTICATED"}):
   identity==="admin"?reply.code(200).send({operation:"synthetic-admin"}):
   reply.code(403).send({error:"FORBIDDEN"});
 });
 app.get("/fixture/me",async(req,reply)=>{
  const identity=authentication(req.headers);
  return identity?reply.code(200).send({identity,role:IDENTITIES[identity].role}):reply.code(401).send({error:"UNAUTHENTICATED"});
 });
 const evaluations:Evaluation[]=[];
 const capture=async(ruleId:string,identity:Identity|null,operationKey:string,credential:string|null,
    overrideExpected?:"ALLOW"|"DENY",reason="TRUSTED_FIXTURE_POLICY")=>{
  if(evaluations.length>=max||Date.now()>deadline)throw new FixtureConfigError("FIXTURE_EVALUATION_BOUND_EXCEEDED");
  const op=FIXTURE_OPERATIONS.find(x=>x.key===operationKey);
  if(!op)throw new FixtureConfigError("FIXTURE_OPERATION_NOT_ALLOWED");
  let headers:Record<string,string>={};
  if(credential){
   if(scheme==="BEARER"||scheme==="OAUTH2")headers={authorization:"Bearer "+credential};
   if(scheme==="API_KEY")headers={"x-fixture-api-key":credential};
   if(scheme==="BASIC")headers={authorization:"Basic "+Buffer.from("synthetic:"+credential).toString("base64")};
   if(scheme==="SESSION")headers={cookie:"fixture_session="+credential};
  }
  const res=await app.inject({method:op.method as "GET"|"POST",url:op.path,headers});
  const observed:"ALLOW"|"DENY"|"UNKNOWN"=res.statusCode>=200&&res.statusCode<300?"ALLOW":
   [401,403].includes(res.statusCode)?"DENY":"UNKNOWN";
  const should=overrideExpected??expected(identity,operationKey);
  const result=observed==="UNKNOWN"?"UNKNOWN":observed===should?"PASS":"DEVIATION";
  const fp=sha([AUTH_ENGINE_VERSION,fixture,scheme,ruleId,identity??"anonymous",operationKey,should,observed].join("|"));
  evaluations.push({ruleId,revision:"1",identity:identity??"anonymous",role:identity?IDENTITIES[identity].role:"anonymous",
   operationKey,expected:should,observed,status:res.statusCode,responseBytes:Buffer.byteLength(res.body),
   result,reason, fingerprint:fp,fixtureOnly:true,confidence:result==="UNKNOWN"?"LOW":"HIGH"});
 };
 try{
  await app.ready();
  const a=issue("user-a"),b=issue("user-b"),m=issue("manager"),admin=issue("admin");
  await capture("AUTH04_MISSING_CREDENTIAL",null,"FIXTURE_SELF",null);
  await capture("AUTH04_INVALID_CREDENTIAL",null,"FIXTURE_SELF",newSecret());
  const expired=issue("user-a",{expiresAt:Date.now()-1000});
  await capture("AUTH04_EXPIRED",null,"FIXTURE_SELF",expired);
  const revoked=issue("user-a");revoke(revoked);
  await capture("AUTH04_REVOKED",null,"FIXTURE_SELF",revoked);
  const wrongIssuer=issue("user-a",{issuer:"untrusted-synthetic-issuer"});
  await capture("AUTH04_WRONG_ISSUER",null,"FIXTURE_SELF",wrongIssuer);
  const wrongAudience=issue("user-a",{audience:"another-synthetic-target"});
  await capture("AUTH04_WRONG_AUDIENCE",null,"FIXTURE_SELF",wrongAudience);
  await capture("AUTH04_TAMPERED",null,"FIXTURE_SELF",a.slice(0,-1)+(a.at(-1)==="x"?"y":"x"));
  await capture("AUTH04_OWN_A","user-a","FIXTURE_RECORD_A",a);
  await capture("AUTH04_OTHER_A","user-a","FIXTURE_RECORD_B",a);
  await capture("AUTH04_OWN_B","user-b","FIXTURE_RECORD_B",b);
  await capture("AUTH04_CROSS_USER_BOLA","user-b","FIXTURE_RECORD_A",b);
  await capture("AUTH04_PRIVILEGED_ISOLATION","manager","FIXTURE_RECORD_A",m);
  await capture("AUTH04_ADMIN_RECORD","admin","FIXTURE_RECORD_A",admin);
  await capture("AUTH04_ADMIN_RESTRICTED","user-a","FIXTURE_ADMIN",a);
  await capture("AUTH04_ADMIN_ALLOWED","admin","FIXTURE_ADMIN",admin);
  await capture("AUTH04_ANONYMOUS_ADMIN",null,"FIXTURE_ADMIN",null);
  const fresh=rotate(a,"user-a");
  await capture("AUTH04_ROTATED_OLD",null,"FIXTURE_SELF",a);
  await capture("AUTH04_ROTATED_NEW","user-a","FIXTURE_SELF",fresh);
  const session=issue("user-b");revoke(session);
  await capture("AUTH04_LOGOUT_INVALIDATION",null,"FIXTURE_SELF",session);
  await capture("AUTH04_SESSION_CROSS_IDENTITY","user-a","FIXTURE_RECORD_B",fresh);
  await capture("AUTH04_ROLE_CLAIM_IGNORED","user-a","FIXTURE_ADMIN",fresh);
  if(rotations!==1)throw new FixtureConfigError("CREDENTIAL_ROTATION_FAILED");
  const counts={attempted:evaluations.length,passed:evaluations.filter(e=>e.result==="PASS").length,
   deviations:evaluations.filter(e=>e.result==="DEVIATION").length,unknown:evaluations.filter(e=>e.result==="UNKNOWN").length,skipped:0};
  return {fixtureVersion:fixture,engineVersion:AUTH_ENGINE_VERSION,scheme,evaluations,coverage:counts,
   limitations:["Synthetic isolated Fastify.inject fixture only; never the customer API.",
    "Real Host verification, credential vault and external network permits unavailable.",
    "Fixture role policy does not infer customer operation authorization.",
    "UNKNOWN != SAFE; No evidence != safe; FIX APPLIED != VERIFIED_FIXED."],
   runtimeValidation:false,customerNetworkRequests:0};
 }finally{
  tokens.clear();
  await app.close();
 }
}
