import {createHash} from "node:crypto";
import {DETECTION_ENGINE,DETECTION_FIXTURE,DETECTION_FIXTURE_REVISION,type Actor,type DetectionPath,type Evidence,type Profile} from "./security-fixture.js";

export type RuleId="PT-AUTH-ANONYMOUS"|"PT-AUTH-INVALID"|"PT-AUTH-EXPIRED"|"PT-AUTH-REVOKED"|
 "PT-BOLA-CROSS-USER"|"PT-FUNCTION-ROLE"|"PT-SENSITIVE-FIELD"|"PT-CONFIDENTIAL-CACHE";
export type Case={caseId:string;method:"GET";path:DetectionPath;actor:Actor;expectedStatus:number};
export type Rule={id:RuleId;revision:"1.0.0";category:string;path:DetectionPath;cases:readonly Case[];
 impact:"LOW"|"MEDIUM"|"HIGH";remediation:string;description:string};
const auth=(id:RuleId,actor:Actor):Rule=>({
 id,revision:"1.0.0",category:"AUTHENTICATION",path:"/pt/account",
 cases:[{caseId:"valid",method:"GET",path:"/pt/account",actor:"alice",expectedStatus:200},
  {caseId:"challenge",method:"GET",path:"/pt/account",actor,expectedStatus:401}],
 impact:"MEDIUM",description:"Synthetic protected account rejects untrusted credential state",
 remediation:"Enforce server-side authentication for the protected operation and reject invalid credential states"
});
export const RULES:readonly Rule[]=[
 auth("PT-AUTH-ANONYMOUS","anonymous"),auth("PT-AUTH-INVALID","invalid"),
 auth("PT-AUTH-EXPIRED","expired"),auth("PT-AUTH-REVOKED","revoked"),
 {id:"PT-BOLA-CROSS-USER",revision:"1.0.0",category:"OBJECT_AUTHORIZATION",path:"/pt/resources/bob",
 cases:[{caseId:"owner",method:"GET",path:"/pt/resources/bob",actor:"bob",expectedStatus:200},
  {caseId:"foreign",method:"GET",path:"/pt/resources/bob",actor:"alice",expectedStatus:403}],
 impact:"HIGH",description:"Only the resource owner or authorized synthetic administrator may read Bob's resource",
 remediation:"Authorize resource ownership server-side on every object access"},
 {id:"PT-FUNCTION-ROLE",revision:"1.0.0",category:"FUNCTION_AUTHORIZATION",path:"/pt/admin",
 cases:[{caseId:"admin",method:"GET",path:"/pt/admin",actor:"admin",expectedStatus:200},
  {caseId:"standard",method:"GET",path:"/pt/admin",actor:"alice",expectedStatus:403}],
 impact:"MEDIUM",description:"The synthetic privileged operation requires administrator authorization",
 remediation:"Enforce role and permission checks on privileged API operations"},
 {id:"PT-SENSITIVE-FIELD",revision:"1.0.0",category:"SENSITIVE_RESPONSE",path:"/pt/confidential",
 cases:[{caseId:"confidential",method:"GET",path:"/pt/confidential",actor:"alice",expectedStatus:200}],
 impact:"MEDIUM",description:"The synthetic confidential response must not expose the forbidden internal marker",
 remediation:"Apply explicit response allowlists and exclude confidential fields"},
 {id:"PT-CONFIDENTIAL-CACHE",revision:"1.0.0",category:"RESPONSE_CONTROL",path:"/pt/confidential",
 cases:[{caseId:"confidential",method:"GET",path:"/pt/confidential",actor:"alice",expectedStatus:200}],
 impact:"LOW",description:"The synthetic confidential response requires private, no-store cache directives",
 remediation:"Set Cache-Control: private, no-store for explicitly confidential responses"}
];
export type Status="PASS"|"OBSERVED"|"INCONCLUSIVE"|"SKIPPED";
export type Result={ruleId:RuleId;revision:"1.0.0";status:Status;code:string;
 category:string;impact:string;confidence:"HIGH"|"NONE";
 evidence:readonly Evidence[];fingerprint:string|null;remediation:string;
 syntheticOnly:true;runtimeCustomerVerification:false};
export function getRule(id:string):Rule|undefined{return RULES.find(x=>x.id===id);}
export function planRules(ids:readonly string[]):Rule[]{
 if(!ids.length||ids.length>RULES.length||new Set(ids).size!==ids.length)
  throw new Error("INVALID_DETECTION_RULE_SELECTION");
 return ids.map(id=>{const r=getRule(id);if(!r)throw new Error("UNKNOWN_DETECTION_RULE");return r;});
}
export function evaluateRule(rule:Rule,profile:Profile,evidence:readonly Evidence[]):Result{
 const base={ruleId:rule.id,revision:rule.revision,category:rule.category,impact:rule.impact,
  remediation:rule.remediation,syntheticOnly:true as const,runtimeCustomerVerification:false as const};
 const missing=rule.cases.some((c,i)=>{
  const x=evidence[i];
  return !x||x.profile!==profile||x.path!==c.path||x.method!==c.method||x.actor!==c.actor||
   x.fixtureVersion!==DETECTION_FIXTURE_REVISION||x.outcome!=="FIXTURE_RESPONSE"||
   !/^[0-9a-f]{64}$/.test(x.responseHash)||x.responseBytes>2048;
 });
 if(missing||evidence.length!==rule.cases.length)return {...base,status:"INCONCLUSIVE",code:"MISSING_OR_UNTRUSTED_EVIDENCE",
  evidence:[],fingerprint:null,confidence:"NONE"};
 // A positive assertion requires the trusted baseline comparison to have succeeded first.
 const baseline=rule.cases.slice(0,-1).every((c,i)=>evidence[i]!.status===c.expectedStatus);
 if(!baseline)return {...base,status:"INCONCLUSIVE",code:"CONTROL_PRECONDITION_FAILED",
  evidence,fingerprint:null,confidence:"NONE"};
 const last=evidence[evidence.length-1]!;
 const expected=rule.cases[rule.cases.length-1]!.expectedStatus;
 let observed=false;
 if(rule.id==="PT-SENSITIVE-FIELD"){
  if(last.status!==200)return {...base,status:"INCONCLUSIVE",code:"CONFIDENTIAL_RESOURCE_UNAVAILABLE",evidence,fingerprint:null,confidence:"NONE"};
  observed=last.exposedPaths.includes("$.internalAccessToken");
 }else if(rule.id==="PT-CONFIDENTIAL-CACHE"){
  if(last.status!==200)return {...base,status:"INCONCLUSIVE",code:"CONFIDENTIAL_RESOURCE_UNAVAILABLE",evidence,fingerprint:null,confidence:"NONE"};
  observed=!last.cacheControl?.toLowerCase().includes("no-store")||!last.cacheControl?.toLowerCase().includes("private");
 }else{
  // 2xx is sufficient only with explicit trusted policy and successful positive control.
  if(last.status!==expected&&last.status!==200)
   return {...base,status:"INCONCLUSIVE",code:"UNEXPECTED_HTTP_SEMANTICS",evidence,fingerprint:null,confidence:"NONE"};
  observed=last.status===200;
 }
 const fingerprint=observed?createHash("sha256").update(JSON.stringify({
  engine:DETECTION_ENGINE,fixture:DETECTION_FIXTURE,fixtureVersion:DETECTION_FIXTURE_REVISION,
  rule:rule.id,revision:rule.revision,profile,path:rule.path,
  observedStatuses:evidence.map(x=>x.status),
  evidenceHashes:evidence.map(x=>x.responseHash)
 })).digest("hex"):null;
 return {...base,status:observed?"OBSERVED":"PASS",code:observed?"SYNTHETIC_POLICY_VIOLATION":"EXPECTED_POLICY_ENFORCED",
  evidence,fingerprint,confidence:observed?"HIGH":"NONE"};
}
export function skippedRule(rule:Rule,reason:string):Result{return {
 ruleId:rule.id,revision:rule.revision,category:rule.category,impact:rule.impact,remediation:rule.remediation,
 status:"SKIPPED",code:reason,confidence:"NONE",evidence:[],fingerprint:null,
 syntheticOnly:true,runtimeCustomerVerification:false
};}

/** JSONB property order is not stable; sign the canonical immutable plan content. */
function canonical(value:unknown):unknown{
 if(Array.isArray(value))return value.map(canonical);
 if(value!==null&&typeof value==="object")
  return Object.fromEntries(Object.entries(value as Record<string,unknown>).sort(([a],[b])=>a.localeCompare(b))
   .map(([k,v])=>[k,canonical(v)]));
 return value;
}
export function planFingerprint(value:unknown):string{
 return createHash("sha256").update(JSON.stringify(canonical(value))).digest("hex");
}
