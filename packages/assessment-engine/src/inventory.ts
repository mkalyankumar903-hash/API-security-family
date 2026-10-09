import {createHash} from "node:crypto";
import type {Inventory,DiscoveredOperation,Format} from "../../discovery/src/index.js";

// This engine consumes ONLY immutable Phase 02 projections. It deliberately never parses URLs,
// expands variables, fetches references, reads files or executes requests.
export const INVENTORY_ENGINE_VERSION="inventory-v1" as const;
export const CANONICAL_VERSION="canonical-json-v1" as const;
type Impact="INFORMATIONAL"|"LOW"|"MEDIUM"|"HIGH";
type Confidence="HIGH"|"MEDIUM";
type Facts=Record<string,string|number|boolean|null>;
export type Rule={id:string;revision:"1.0.0";name:string;category:string;formats:Format[];
 impact:Impact;confidence:Confidence;explanation:string;potentialImpact:string;remediation:string;limitation:string;unsupported?:string};
export type Detection={fingerprint:string;correlationKey:string;ruleId:string;ruleRevision:string;operationKey:string|null;
 pointer:string;format:Format;category:string;impact:Impact;confidence:Confidence;validationLevel:"SPEC_OBSERVATION";
 reviewRequired:true;explanation:string;potentialImpact:string;remediation:string;limitations:string[];
 evidence:{kind:"DIRECT_DECLARATION"|"DETERMINISTIC_DERIVATION";pointer:string;facts:Facts;inventoryFingerprint:string}};
export type RuleCoverage={ruleId:string;revision:string;status:"EVALUATED"|"SKIPPED";applicableOperations:number;matches:number;reason:string|null};
export type DetectionResult={engineVersion:typeof INVENTORY_ENGINE_VERSION;canonicalVersion:typeof CANONICAL_VERSION;
 rawFingerprint:string;normalizedFingerprint:string;observations:Detection[];coverage:RuleCoverage[];warnings:string[];limitations:string[]};
const ALL:Format[]=["OPENAPI_3_0","OPENAPI_3_1","SWAGGER_2","POSTMAN_2_1"];
const OAS:Format[]=["OPENAPI_3_0","OPENAPI_3_1","SWAGGER_2"];
const catalog:Rule[]=[
 ["AUTH_UNDECLARED","Missing declared authentication","AUTH","LOW","HIGH","No effective authentication requirement is declared.","The intended authentication policy is unclear.","Declare requirements and verify enforcement.","Missing declarations never prove absent runtime authentication."],
 ["AUTH_EXPLICIT_NONE","Explicitly unauthenticated operation","AUTH","LOW","HIGH","An operation explicitly opts out of declared authentication.","Anonymous exposure may be intentional or may merit review.","Confirm public exposure is intended and document access rules.","Does not confirm runtime anonymous access."],
 ["AUTH_SENSITIVE_ROUTE","Sensitive-looking route without declared authentication","AUTH","MEDIUM","MEDIUM","A potentially sensitive operation has no declared authentication.","Undocumented access policy for sensitive functionality.","Review server-side authentication and authorization; declare intended policy.","Route naming is a heuristic, not evidence of BOLA or BFLA."],
 ["AUTH_WRITE_PUBLIC","Write method explicitly declared anonymous","AUTH","MEDIUM","HIGH","A write-capable operation is explicitly declared unauthenticated.","An intended public mutation may need additional safeguards.","Confirm anonymous mutation is intentional; verify server-side controls.","No mutation is executed or confirmed accessible."],
 ["AUTH_OVERRIDE_WEAKENS","Operation override weakens inherited security","AUTH","MEDIUM","MEDIUM","A security override weakens inherited requirements.","Inconsistent intended authentication.","Document operation-level exceptions.","Inherited scheme detail is not retained in inventory.","Inherited requirements cannot be safely reconstructed."],
 ["AUTH_APIKEY_QUERY","API key declared in query","AUTH","MEDIUM","HIGH","An API-key scheme is declared in a URL query parameter.","Query credentials can be exposed through URL handling.","Prefer an authorization header and review logging.","The importer never accesses or stores key values."],
 ["AUTH_BASIC","HTTP Basic authentication declared","AUTH","LOW","HIGH","The specification declares HTTP Basic authentication.","Credential exposure risk if TLS or implementation is weak.","Prefer stronger schemes and verify TLS enforcement.","Does not prove insecure transport."],
 ["AUTH_OAUTH_SCOPE","Undeclared OAuth scope reference","AUTH","LOW","MEDIUM","A required OAuth scope is not defined in the scheme.","Documentation may misrepresent authorization requirements.","Reconcile operation scopes with OAuth flow declarations.","Normalized projection does not retain declared scope keys.","OAuth flow scope definitions are unavailable."],
 ["AUTH_UNKNOWN_SCHEME","Undefined or invalid security scheme","AUTH","LOW","HIGH","A referenced security scheme is not defined.","Broken security documentation.","Correct referenced scheme names.","Phase 02 rejects invalid references at ingestion.","Invalid schemes are already rejected during import."],
 ["AUTH_INCONSISTENCY","Inconsistent related-operation authorization","AUTH","LOW","MEDIUM","Related operations declare different security semantics.","Policy exceptions deserve review.","Review intended access policy per operation.","Path grouping alone does not establish related authorization.","Conservative related-operation inference unavailable."],
 ["BODY_SCHEMA_MISSING","Declared request body without schema","REQUEST","LOW","HIGH","A declared request body lacks a normalized schema fingerprint.","Validation constraints cannot be determined from its declaration.","Declare a complete request body schema.","Schema enforcement remains unknown."],
 ["STRING_NO_BOUNDS","String parameter missing length bounds","REQUEST","LOW","MEDIUM","A string input lacks explicit length constraints.","Unbounded inputs may need validation.","Declare length limits where appropriate.","Length bounds are not included in Phase 02 parameter projection.","Maximum/minimum length metadata unavailable."],
 ["ARRAY_NO_BOUNDS","Array without size limits","REQUEST","LOW","MEDIUM","An array input lacks declared size limits.","Oversized arrays may increase resource usage.","Add suitable array size limits.","Array size metadata is not present in Phase 02 normalized inventory.","Array size bounds unavailable."],
 ["NUMBER_NO_RANGE","Numeric parameter missing range","REQUEST","LOW","MEDIUM","A numeric parameter has no declared numeric range.","Input domain constraints may be incomplete.","Declare minimum/maximum where appropriate.","An importer-normalized constraint indicator, not validation of runtime enforcement."],
 ["OBJECT_PERMISSIVE","Overly permissive object schema","REQUEST","LOW","MEDIUM","Object schema appears permissive.","Unexpected properties may be accepted.","Review object properties and validation.","Full object schema is not retained in normalized projection.","Object additionalProperties semantics unavailable."],
 ["PATH_PARAMETER_WEAK","Path parameter lacks meaningful schema","REQUEST","LOW","HIGH","A required path parameter has no declared schema type or bounds.","Input shape remains unclear.","Declare concrete path parameter constraints.","Does not prove missing runtime validation."],
 ["ADDITIONAL_PROPERTIES","Unrestricted additional properties","REQUEST","LOW","MEDIUM","Additional object properties are unrestricted.","Potentially broad input shape.","Review additionalProperties policy.","Full schema keyword unavailable.","additionalProperties is not projected."],
 ["REQUEST_SENSITIVE_FIELD","Sensitive-looking required request fields","REQUEST","INFORMATIONAL","MEDIUM","A request schema includes a sensitive-looking required field.","Credential or personal data handling may deserve review.","Check minimization, transport, logging and redaction.","Names alone are not proof of a vulnerability."],
 ["ERROR_RESPONSE_GAPS","No documented error responses","RESPONSE","LOW","MEDIUM","Error response coverage appears incomplete.","API error behavior may be undocumented.","Document relevant error states.","Contentless responses are not represented in the normalized shape list.","Response status-only declarations unavailable."],
 ["RESPONSE_SENSITIVE_FIELD","Sensitive-looking required response fields","RESPONSE","LOW","MEDIUM","A response schema declares a sensitive-looking required field.","Sensitive data exposure should be manually reviewed.","Review response minimization and access controls.","Field names do not prove data leakage."],
 ["EXAMPLE_CREDENTIAL","Credential-like example values","RESPONSE","MEDIUM","HIGH","Credential-like examples occur in documentation.","Example secrets may be exposed.","Replace with placeholders and rotate any real credentials.","Raw examples are never retained in sanitized inventory.","Raw example values deliberately unavailable."],
 ["DESCRIPTION_SENSITIVE_EXAMPLE","Sensitive-looking embedded description payload","RESPONSE","LOW","MEDIUM","Descriptions may include sensitive examples.","Unintended disclosure in documentation.","Redact secret-like examples.","Import sanitizes descriptions; raw payload inspection is prohibited.","Raw descriptions deliberately unavailable."],
 ["RESPONSE_SCHEMA_INCONSISTENT","Inconsistent comparable response schemas","RESPONSE","LOW","MEDIUM","Similar operations use differing response schemas.","Clients may depend on inconsistent contracts.","Review related response schema choices.","Comparable operations cannot be confidently identified.","Insufficient comparability evidence."],
 ["HTTP_SERVER","Insecure HTTP server declaration","TRANSPORT","MEDIUM","HIGH","Specification explicitly declares an HTTP URL.","Transport security may be incomplete.","Prefer HTTPS and verify TLS enforcement.","Does not prove the service accepts cleartext traffic."],
 ["UNRESOLVED_SERVER","Unresolvable offline server declaration","TRANSPORT","INFORMATIONAL","HIGH","Server location cannot be determined from offline metadata.","Runtime endpoint coverage is unknown.","Manually review server templates.","No DNS or network resolution attempted."],
 ["DEPRECATED_OPERATION","Deprecated operation present","METADATA","INFORMATIONAL","HIGH","An operation is marked deprecated.","Old interfaces can extend maintenance and attack surface.","Confirm retirement timeline and client migration.","Deprecated does not mean vulnerable."],
 ["DEPRECATED_AUTH_SCHEME","Deprecated authentication scheme","METADATA","LOW","MEDIUM","A legacy authentication scheme appears in the declaration.","Older authentication patterns may need review.","Review and migrate legacy authentication.","Basic authentication is only a heuristic for legacy schemes."],
 ["UNSUPPORTED_SECURITY_METADATA","Unsupported security declaration metadata","METADATA","INFORMATIONAL","HIGH","Authentication metadata cannot be interpreted fully.","Assessment coverage is incomplete.","Review unsupported authentication manually.","Coverage warning is not a security vulnerability.","Unknown security metadata must be reported as coverage, not a finding."]
].map((r):Rule=>({id:"API03_"+r[0],revision:"1.0.0",name:r[1],category:r[2],impact:r[3] as Impact,
confidence:r[4] as Confidence,explanation:r[5],potentialImpact:r[6],remediation:r[7],limitation:r[8],
formats:["API03_AUTH_APIKEY_QUERY","API03_AUTH_OAUTH_SCOPE","API03_AUTH_UNKNOWN_SCHEME","API03_BODY_SCHEMA_MISSING","API03_STRING_NO_BOUNDS","API03_ARRAY_NO_BOUNDS","API03_NUMBER_NO_RANGE","API03_OBJECT_PERMISSIVE","API03_PATH_PARAMETER_WEAK","API03_ADDITIONAL_PROPERTIES","API03_REQUEST_SENSITIVE_FIELD","API03_ERROR_RESPONSE_GAPS","API03_RESPONSE_SENSITIVE_FIELD","API03_EXAMPLE_CREDENTIAL","API03_DESCRIPTION_SENSITIVE_EXAMPLE","API03_RESPONSE_SCHEMA_INCONSISTENT"].includes("API03_"+r[0])?OAS:ALL,
...(r[9]?{unsupported:r[9]}:{})}));
export const RULE_CATALOG:ReadonlyArray<Readonly<Rule>>=Object.freeze(catalog.map(x=>Object.freeze(x)));
const hash=(s:string)=>createHash("sha256").update(s).digest("hex");
export function canonical(value:unknown):string {
 if(Array.isArray(value))return "["+value.map(canonical).join(",")+"]";
 if(value&&typeof value==="object")return "{"+Object.keys(value).sort().map(key=>JSON.stringify(key)+":"+canonical((value as Record<string,unknown>)[key])).join(",")+"}";
 return JSON.stringify(value)??"null";
}
const sensitive=(s:string)=>/(?:^|[_-])(password|passwd|secret|token|private[_-]?key|api[_-]?key|ssn)(?:$|[_-])/i.test(s);
const unauth=(o:DiscoveredOperation)=>["EXPLICIT_NONE","UNDECLARED"].includes(o.auth.state);
function match(rule:Rule,inv:Inventory,o:DiscoveredOperation|null):{pointer:string;kind:"DIRECT_DECLARATION"|"DETERMINISTIC_DERIVATION";facts:Facts}[] {
 const key=rule.id.slice(6),results:{pointer:string;kind:"DIRECT_DECLARATION"|"DETERMINISTIC_DERIVATION";facts:Facts}[]=[];
 const add=(pointer:string,facts:Facts,kind:"DIRECT_DECLARATION"|"DETERMINISTIC_DERIVATION"="DIRECT_DECLARATION")=>{
  if(!pointer.startsWith("/")||pointer.length>1500)throw new Error("EVIDENCE_POINTER_INVALID");
  results.push({pointer,kind,facts});
 };
 if(!o) {
  if(key==="HTTP_SERVER")inv.metadata.servers.forEach((server,i)=>{if(/^http:\/\//i.test(server))add("/servers/"+i,{scheme:"http"});});
  if(key==="UNRESOLVED_SERVER"&&inv.metadata.warnings.includes("UNRESOLVED_SERVER_TEMPLATE"))
   add("/servers",{serverTemplateUnresolved:true});
  return results;
 }
 switch(key){
  case "AUTH_UNDECLARED":if(o.auth.state==="UNDECLARED")add(o.auth.source,{state:o.auth.state});break;
  case "AUTH_EXPLICIT_NONE":if(o.auth.state==="EXPLICIT_NONE")add(o.auth.source,{state:o.auth.state});break;
  case "AUTH_SENSITIVE_ROUTE":if(unauth(o)&&/(?:^|\/)(admin|billing|payments|accounts|users|secrets|keys|tokens)(?:\/|$|\{)/i.test(o.path))
   add(o.pointer,{authState:o.auth.state,sensitivePathHeuristic:true},"DETERMINISTIC_DERIVATION");break;
  case "AUTH_WRITE_PUBLIC":if(o.auth.state==="EXPLICIT_NONE"&&["POST","PUT","PATCH","DELETE"].includes(o.method))
   add(o.auth.source,{method:o.method,explicitlyUnauthenticated:true});break;
  case "AUTH_APIKEY_QUERY":if(Object.keys(o.auth.requirements.flatMap(x=>Object.keys(x)).reduce((a,k)=>({...a,[k]:true}),{})).some(k=>inv.schemes[k]?.type==="apiKey"&&inv.schemes[k]?.in==="query"))
   add(o.auth.source,{apiKeyInQuery:true});break;
  case "AUTH_BASIC":if(o.auth.requirements.some(r=>Object.keys(r).some(k=>inv.schemes[k]?.type==="http-basic"||inv.schemes[k]?.scheme?.toLowerCase()==="basic")))
   add(o.auth.source,{basicAuthentication:true});break;
  case "BODY_SCHEMA_MISSING":o.requestBodies.forEach(s=>{if(!s.schemaFingerprint)add(s.pointer,{bodyDeclared:true,schemaMissing:true});});break;
  case "NUMBER_NO_RANGE":o.parameters.forEach(p=>{if(["integer","number"].includes(p.type??"")&&p.constraints.minimum===undefined&&p.constraints.maximum===undefined)
   add(p.pointer,{parameterLocation:p.in,numericBoundsDeclared:false});});break;
  case "PATH_PARAMETER_WEAK":o.parameters.forEach(p=>{if(p.in==="path"&&p.required&&!p.type)add(p.pointer,{required:true,schemaTypeKnown:false});});break;
  case "REQUEST_SENSITIVE_FIELD":o.requestBodies.forEach(s=>{const n=s.requiredProperties.filter(sensitive).length;if(n)add(s.pointer,{sensitiveRequiredFieldCount:n});});break;
  case "RESPONSE_SENSITIVE_FIELD":o.responses.forEach(s=>{const n=s.requiredProperties.filter(sensitive).length;if(n)add(s.pointer,{sensitiveRequiredFieldCount:n,responseStatus:s.status});});break;
  case "DEPRECATED_OPERATION":if(o.deprecated)add(o.pointer,{deprecated:true});break;
  case "DEPRECATED_AUTH_SCHEME":if(o.auth.requirements.some(r=>Object.keys(r).some(k=>inv.schemes[k]?.type==="http-basic")))add(o.auth.source,{legacyBasicScheme:true});break;
 }
 return results;
}
const docRules=new Set(["API03_HTTP_SERVER","API03_UNRESOLVED_SERVER"]);
export function detectInventory(inv:Inventory):DetectionResult {
 if(inv.normalizationVersion!=="phase02-v1"||!ALL.includes(inv.format)||
 !/^[a-f0-9]{64}$/.test(inv.normalizedFingerprint)||!/^[a-f0-9]{64}$/.test(inv.rawFingerprint))
 throw new Error("UNSUPPORTED_OR_TAMPERED_INVENTORY");
 if(inv.operations.length>5000)throw new Error("INVENTORY_BUDGET_EXCEEDED");
 const observations:Detection[]=[],coverage:RuleCoverage[]=[];
 for(const rule of RULE_CATALOG){
  let reason=rule.unsupported??(!rule.formats.includes(inv.format)?"FORMAT_SEMANTICS_UNAVAILABLE":null);
  const applicable=docRules.has(rule.id)?1:inv.operations.length;
  if(inv.format==="POSTMAN_2_1"&&["API03_DEPRECATED_AUTH_SCHEME"].includes(rule.id))
   reason="POSTMAN_AUTH_METADATA_NOT_FORMAL_SCHEME";
  let matches=0;
  if(!reason)for(const op of docRules.has(rule.id)?[null]:inv.operations){
   for(const hit of match(rule,inv,op)){
    const correlationKey=hash(canonical({version:CANONICAL_VERSION,ruleId:rule.id,revision:rule.revision,operationKey:op?.key??null,pointer:hit.pointer}));
    const evidence={kind:hit.kind,pointer:hit.pointer,facts:hit.facts,inventoryFingerprint:inv.normalizedFingerprint};
    const fingerprint=hash(canonical({correlationKey,evidence,impact:rule.impact,confidence:rule.confidence}));
    observations.push({fingerprint,correlationKey,ruleId:rule.id,ruleRevision:rule.revision,operationKey:op?.key??null,
      pointer:hit.pointer,format:inv.format,category:rule.category,impact:rule.impact,confidence:rule.confidence,
      validationLevel:"SPEC_OBSERVATION",reviewRequired:true,explanation:rule.explanation,potentialImpact:rule.potentialImpact,
      remediation:rule.remediation,limitations:[rule.limitation],evidence});matches++;
    if(observations.length>20000)throw new Error("OBSERVATION_BUDGET_EXCEEDED");
   }
  }
  coverage.push({ruleId:rule.id,revision:rule.revision,status:reason?"SKIPPED":"EVALUATED",applicableOperations:reason?0:applicable,matches,reason});
 }
 observations.sort((a,b)=>a.ruleId.localeCompare(b.ruleId)||a.pointer.localeCompare(b.pointer)||a.fingerprint.localeCompare(b.fingerprint));
 return {engineVersion:INVENTORY_ENGINE_VERSION,canonicalVersion:CANONICAL_VERSION,rawFingerprint:inv.rawFingerprint,
  normalizedFingerprint:inv.normalizedFingerprint,observations,coverage,warnings:[...new Set(inv.metadata.warnings)].sort(),
  limitations:["SPEC_ONLY: maxRequests = 0; methods = []","UNKNOWN != SAFE","NO EVIDENCE != SAFE","FIX APPLIED != VERIFIED_FIXED",
  "No authenticated runtime tests, endpoint probing, exploit verification or Host findings promotion.","Coverage warnings and skipped rules are not vulnerabilities."]};
}
export function compareDetection(a:DetectionResult,b:DetectionResult){
 if(a.engineVersion!==b.engineVersion||a.canonicalVersion!==b.canonicalVersion||
 a.coverage.map(x=>x.ruleId+":"+x.revision+":"+x.status).join("|")!==b.coverage.map(x=>x.ruleId+":"+x.revision+":"+x.status).join("|"))
 return {comparable:false,reason:"RULE_VERSION_OR_COVERAGE_INCOMPATIBLE",newlyObserved:[],noLongerObserved:[],stillObserved:[],changed:[]};
 const previous=new Map(a.observations.map(x=>[x.correlationKey,x])),next=new Map(b.observations.map(x=>[x.correlationKey,x]));
 return {comparable:true,reason:null,
 newlyObserved:b.observations.filter(x=>!previous.has(x.correlationKey)),
 noLongerObserved:a.observations.filter(x=>!next.has(x.correlationKey)),
 stillObserved:b.observations.filter(x=>previous.get(x.correlationKey)?.fingerprint===x.fingerprint),
 changed:b.observations.filter(x=>previous.has(x.correlationKey)&&previous.get(x.correlationKey)?.fingerprint!==x.fingerprint),
 limitation:"No longer observed in documentation is NOT VERIFIED_FIXED. Runtime behavior remains UNKNOWN."};
}
