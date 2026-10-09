import {createHash} from "node:crypto";
import type {Inventory} from "../../discovery/src/index.js";
import type {RichInventory,RichOperation} from "../../discovery/src/rich.js";
import {canonical,detectInventory,RULE_CATALOG,type Detection,type DetectionResult} from "./inventory.js";

/** Versioned deterministic extension: never mutates or re-evaluates existing inventory-v1 reports.
 * Only already validated, immutable, redacted phase05-v2 metadata may be evaluated. */
export const RICH_ENGINE_VERSION="inventory-v2" as const;
const hash=(v:unknown)=>createHash("sha256").update(canonical(v)).digest("hex");
type Extended=Omit<DetectionResult,"engineVersion">&{engineVersion:typeof RICH_ENGINE_VERSION;richFingerprint:string};
type Key="AUTH_OVERRIDE_WEAKENS"|"AUTH_OAUTH_SCOPE"|"STRING_NO_BOUNDS"|"ARRAY_NO_BOUNDS"|"ADDITIONAL_PROPERTIES"|"ERROR_RESPONSE_GAPS";
const RULES:Record<Key,{field:keyof RichOperation;reason:string}>={
 AUTH_OVERRIDE_WEAKENS:{field:"weakensInherited",reason:"SECURITY_OVERRIDE_NOT_COMPARABLE"},
 AUTH_OAUTH_SCOPE:{field:"unknownOAuthScopes",reason:"OAUTH_SCOPE_DECLARATION_UNKNOWN"},
 STRING_NO_BOUNDS:{field:"unboundedStrings",reason:"PARAMETER_REFERENCE_UNRESOLVED"},
 ARRAY_NO_BOUNDS:{field:"unboundedArrays",reason:"PARAMETER_REFERENCE_UNRESOLVED"},
 ADDITIONAL_PROPERTIES:{field:"explicitAdditionalProperties",reason:"REQUEST_BODY_REFERENCE_UNRESOLVED"},
 ERROR_RESPONSE_GAPS:{field:"missingErrorResponses",reason:"RESPONSE_STATUS_UNAVAILABLE"}
};
const values=(r:RichOperation,k:Key):number|null=>{
 const v=r[RULES[k].field];return typeof v==="boolean"?(v?1:0):typeof v==="number"?v:null;
};
export function detectRichInventory(inventory:Inventory,rich:RichInventory):Extended{
 if(inventory.normalizationVersion!=="phase02-v1"||rich.normalizationVersion!=="phase05-v2"||
  rich.rawFingerprint!==inventory.rawFingerprint||rich.phase02Fingerprint!==inventory.normalizedFingerprint||
  rich.richFingerprint!==hash({normalizationVersion:rich.normalizationVersion,rawFingerprint:rich.rawFingerprint,
   phase02Fingerprint:rich.phase02Fingerprint,operations:rich.operations})||
  rich.operations.length!==inventory.operations.length||
  rich.operations.some((x,i)=>x.key!==inventory.operations[i]?.key))
  throw new Error("RICH_INVENTORY_INTEGRITY_FAILURE");
 const base=detectInventory(inventory);
 const findings:Detection[]=[...base.observations];
 const ruleCoverage=base.coverage.map(row=>({...row}));
 for(const key of Object.keys(RULES) as Key[]){
  const id="API03_"+key,rule=RULE_CATALOG.find(x=>x.id===id);
  if(!rule)throw new Error("RICH_RULE_NOT_IN_CATALOG");
  const coverage=ruleCoverage.find(x=>x.ruleId===id);
  if(!coverage)throw new Error("RICH_COVERAGE_MISSING");
  const vals=rich.operations.map(x=>values(x,key));
  const unresolved=vals.some(x=>x===null);
  if(unresolved||!rule.formats.includes(inventory.format)){
   coverage.status="SKIPPED";
   coverage.reason=unresolved?RULES[key].reason:"FORMAT_SEMANTICS_UNAVAILABLE";
   continue;
  }
  coverage.status="EVALUATED";coverage.reason=null;coverage.revision="2.0.0";
  coverage.applicableOperations=rich.operations.length;coverage.matches=0;
  for(let i=0;i<rich.operations.length;i++){
   const op=rich.operations[i]!,n=vals[i]!;
   if(n<=0)continue;
   const facts:{declarationCount:number;runtimeVerified:false}={declarationCount:n,runtimeVerified:false};
   const pointer=op.pointer+"/"+key.toLowerCase();
   const correlationKey=hash({version:"phase05-canonical-v2",id,revision:"2.0.0",operationKey:op.key});
   const evidence={kind:"DETERMINISTIC_DERIVATION" as const,pointer,
      facts,inventoryFingerprint:rich.richFingerprint};
   const fingerprint=hash({correlationKey,evidence,impact:rule.impact,confidence:rule.confidence});
   findings.push({fingerprint,correlationKey,ruleId:id,ruleRevision:"2.0.0",operationKey:op.key,
     pointer,format:inventory.format,category:rule.category,impact:rule.impact,confidence:rule.confidence,
     validationLevel:"SPEC_OBSERVATION",reviewRequired:true,explanation:rule.explanation,
     potentialImpact:rule.potentialImpact,remediation:rule.remediation,limitations:[rule.limitation],evidence});
   coverage.matches++;
  }
 }
 findings.sort((a,b)=>a.ruleId.localeCompare(b.ruleId)||a.pointer.localeCompare(b.pointer)||a.fingerprint.localeCompare(b.fingerprint));
 return {...base,engineVersion:RICH_ENGINE_VERSION,richFingerprint:rich.richFingerprint,
   observations:findings,coverage:ruleCoverage,
   limitations:[...base.limitations,"phase05-v2 metadata applies to new imports only; old phase02-v1 snapshots remain historical."]};
}
