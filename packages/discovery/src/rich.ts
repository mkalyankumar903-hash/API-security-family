import YAML from "yaml";
import {createHash} from "node:crypto";
import type {Inventory} from "./index.js";

/** phase05-v2 is additive; Phase02-v1 normalization is never mutated or rewritten.
 * Source MUST have passed importOfflineDocument() before extraction. No secrets,
 * examples, descriptions, body values or external reference contents are kept. */
type Dict=Record<string,unknown>;
const o=(v:unknown):Dict=>v&&typeof v==="object"&&!Array.isArray(v)?v as Dict:{};
const a=(v:unknown):unknown[]=>Array.isArray(v)?v:[];
const hash=(v:unknown)=>createHash("sha256").update(JSON.stringify(v)).digest("hex");
const types=(v:unknown)=>typeof v==="string"?v:null;
export type RichOperation={
 key:string;pointer:string;
 weakensInherited:boolean|null;unknownOAuthScopes:boolean|null;unboundedStrings:number|null;
 unboundedArrays:number|null;explicitAdditionalProperties:number|null;missingErrorResponses:boolean|null;
};
export type RichInventory={normalizationVersion:"phase05-v2";rawFingerprint:string;phase02Fingerprint:string;richFingerprint:string;operations:RichOperation[]};
const unknown=<T>(v:T|null)=>v===null;
export function buildRichInventory(content:string,inventory:Inventory):RichInventory|null{
 if(inventory.format==="POSTMAN_2_1")return null;
 if(inventory.normalizationVersion!=="phase02-v1"||Buffer.byteLength(content,"utf8")>1048576)throw Error("RICH_SOURCE_NOT_VALIDATED");
 // This function is called only after the existing validation and isolation path succeeds.
 const root=o(content.trimStart().startsWith("{")?JSON.parse(content):YAML.parse(content));
 const schemes=o(inventory.format==="SWAGGER_2"?root.securityDefinitions:o(root.components).securitySchemes);
 const rootSecurity=a(root.security);
 const opData:RichOperation[]=[];
 for(const operation of inventory.operations){
  const path=o(o(root.paths)[operation.originalPath]);
  const raw=o(path[operation.method.toLowerCase()]);
  if(!Object.keys(raw).length)throw Error("RICH_OPERATION_MISMATCH");
  const selected=raw.security;
  const hasOverride=Object.prototype.hasOwnProperty.call(raw,"security");
  const weakensInherited=hasOverride&&rootSecurity.length>0?(Array.isArray(selected)&&selected.length===0?true:
    JSON.stringify(selected)===JSON.stringify(root.security)?false:null):false;
  let unknownOAuthScopes:boolean|null=false;
  for(const req of operation.auth.requirements){
   for(const [name,scopes] of Object.entries(req)){
    const scheme=o(schemes[name]);
    if(scheme.type!=="oauth2")continue;
    let known=new Set<string>();
    if(inventory.format==="SWAGGER_2")known=new Set(Object.keys(o(scheme.scopes)));
    else for(const flow of Object.values(o(scheme.flows)))for(const n of Object.keys(o(o(flow).scopes)))known.add(n);
    if(scopes.some(scope=>!known.has(scope)))unknownOAuthScopes=true;
   }
  }
  const rawParams=[...a(path.parameters),...a(raw.parameters)];
  let strings=0,arrays=0,parametersKnown=true;
  for(const p of rawParams){
   if(o(p).$ref){parametersKnown=false;continue;}
   const parameter=o(p),schema=o(parameter.schema),model=Object.keys(schema).length?schema:parameter;
   if(model.type==="string"&&model.minLength===undefined&&model.maxLength===undefined)strings++;
   if(model.type==="array"&&model.minItems===undefined&&model.maxItems===undefined)arrays++;
  }
  const body=inventory.format==="SWAGGER_2"?o(rawParams.map(o).find(x=>x.in==="body")):
    o(raw.requestBody);
  const bodyRef=Boolean(body.$ref);
  const schemas:unknown[]=inventory.format==="SWAGGER_2"?[body.schema]:
    Object.values(o(body.content)).map(v=>o(v).schema);
  let extra=0,bodyKnown=!bodyRef;
  for(const schemaRaw of schemas){
   const schema=o(schemaRaw);
   if(schema.$ref){bodyKnown=false;continue;}
   if(schema.additionalProperties===true)extra++;
  }
  const statuses=Object.keys(o(raw.responses));
  const missingErrorResponses=statuses.length?(!statuses.some(x=>x==="default"||/^[45]\d\d$/.test(x)||/^[45]XX$/i.test(x))):null;
  opData.push({key:operation.key,pointer:operation.pointer,weakensInherited,unknownOAuthScopes,
   unboundedStrings:parametersKnown?strings:null,unboundedArrays:parametersKnown?arrays:null,
   explicitAdditionalProperties:bodyKnown?extra:null,missingErrorResponses});
 }
 const payload={normalizationVersion:"phase05-v2" as const,rawFingerprint:inventory.rawFingerprint,
  phase02Fingerprint:inventory.normalizedFingerprint,operations:opData};
 return {...payload,richFingerprint:hash(payload)};
}
