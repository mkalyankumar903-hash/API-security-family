import {createHash} from "node:crypto";
import YAML,{visit,isAlias} from "yaml";
import {Validator} from "@platformatic/openapi-schema-validator";
import {parseAndValidateSpec} from "../../assessment-engine/src/index.js";

type Dict=Record<string,unknown>;
export type Format="OPENAPI_3_0"|"OPENAPI_3_1"|"SWAGGER_2"|"POSTMAN_2_1";
export type Auth={state:"DECLARED"|"UNDECLARED"|"EXPLICIT_NONE"|"INHERITED"|"OVERRIDDEN"|"UNKNOWN";source:string;requirements:Record<string,string[]>[]};
export type Parameter={name:string;in:string;required:boolean;type:string|null;format:string|null;schemaFingerprint:string|null;pointer:string;constraints:Dict};
export type Shape={mediaType:string;status:string|null;schemaFingerprint:string|null;type:string|null;requiredProperties:string[];nullable:boolean;composition:string[];pointer:string;description:string|null};
export type DiscoveredOperation={
 key:string;method:string;path:string;originalPath:string;operationId:string|null;
 summary:string|null;description:string|null;tags:string[];folder:string[];
 deprecated:boolean;pointer:string;servers:string[];auth:Auth;parameters:Parameter[];
 requestBodies:Shape[];responses:Shape[];warnings:string[];unresolved:string[];
};
export type Inventory={
 format:Format;normalizationVersion:"phase02-v1";rawFingerprint:string;normalizedFingerprint:string;
 metadata:{title:string|null;declaredVersion:string|null;servers:string[];warnings:string[];coverage:"SUPPORTED_PROFILE"|"PARTIAL"};
 schemes:Record<string,{type:string;in?:string;name?:string;scheme?:string;flows?:string[]}>;
 operations:DiscoveredOperation[];
 assessmentSource:string|null;
};
const sha=(x:string)=>createHash("sha256").update(x).digest("hex");
const obj=(x:unknown):Dict=>x!==null&&typeof x==="object"&&!Array.isArray(x)?x as Dict:{};
const str=(x:unknown):string|null=>typeof x==="string"?x:null;
const arr=(x:unknown):unknown[]=>Array.isArray(x)?x:[];
const jsonPointer=(s:string)=>s.replace(/~/g,"~0").replace(/\//g,"~1");
const maxBytes=1024*1024;
const maxNodes=30000,maxDepth=45,maxRefs=4000,maxOperations=5000;
const methods=["get","put","post","delete","options","head","patch","trace"];
export class DiscoveryError extends Error {constructor(public code:string){super(code);}}
const deny=(s:string):never=>{throw new DiscoveryError(s);};
function stable(x:unknown):string {
 if(Array.isArray(x))return "["+x.map(stable).join(",")+"]";
 if(x&&typeof x==="object")return "{"+Object.keys(x).sort().map(k=>JSON.stringify(k)+":"+stable((x as Dict)[k])).join(",")+"}";
 return JSON.stringify(x)??"null";
}
function safeText(x:unknown,max=200):string|null {
 if(typeof x!=="string")return null;
 const cleaned=[...x].map(ch=>ch.charCodeAt(0)<32||ch.charCodeAt(0)===127?" ":ch).join("").slice(0,max);
 return /(?:bearer\s+\S+|sk_live_|authorization\s*[:=]|password\s*[:=])/i.test(cleaned)?"[REDACTED]":cleaned;
}
function secureParse(content:string):{root:Dict;format:Format;source:unknown} {
 if(typeof content!=="string"||!content.length||Buffer.byteLength(content,"utf8")>maxBytes)deny("DOCUMENT_SIZE_LIMIT");
 if(content.includes("\0")||content.startsWith("PK\u0003\u0004")||content.startsWith("\u001f\u008b"))deny("UNSUPPORTED_BINARY_ARCHIVE");
 let source:unknown;
 try{
  if(/^[\s]*[\x5b\x7b]/.test(content))source=JSON.parse(content);
  else{
   const doc=YAML.parseDocument(content,{uniqueKeys:true,strict:true});
   if(doc.errors.length)deny("INVALID_YAML");
   visit(doc,(_key,node)=>{if(isAlias(node))deny("YAML_ALIAS_PROHIBITED");});
   source=doc.toJS({maxAliasCount:0});
  }
 }catch(e){if(e instanceof DiscoveryError)throw e;deny(/^[\s]*[\x5b\x7b]/.test(content)?"INVALID_JSON":"INVALID_YAML");}
 if(!source||Array.isArray(source)||typeof source!=="object")deny("INVALID_DOCUMENT_ROOT");
 let nodes=0,refs=0;
 const walk=(v:unknown,depth:number)=>{
  if(++nodes>maxNodes||depth>maxDepth)deny("DOCUMENT_COMPLEXITY_LIMIT");
  if(!v||typeof v!=="object")return;
  for(const [k,val] of Object.entries(v)){
   if(k==="$ref"){if(++refs>maxRefs)deny("REFERENCE_COUNT_LIMIT");if(typeof val!=="string"||!val.startsWith("#/"))deny("EXTERNAL_REF_PROHIBITED");}
   walk(val,depth+1);
  }
 };
 walk(source,0);
 const root=obj(source);
 const format:Format=
  typeof root.openapi==="string"&&/^3\.0\.\d+$/.test(root.openapi)?"OPENAPI_3_0":
  typeof root.openapi==="string"&&/^3\.1\.\d+$/.test(root.openapi)?"OPENAPI_3_1":
  root.swagger==="2.0"?"SWAGGER_2":
  obj(root.info).schema==="https://schema.getpostman.com/json/collection/v2.1.0/collection.json"||
    (typeof obj(root.info)._postman_id==="string"&&Array.isArray(root.item))?"POSTMAN_2_1":
  deny("UNSUPPORTED_DOCUMENT_FORMAT");
 return {root,format,source};
}
function resolve(root:Dict,ref:string,trace:string[]=[]):unknown {
 if(!ref.startsWith("#/"))deny("EXTERNAL_REF_PROHIBITED");
 if(trace.includes(ref)||trace.length>16)deny("LOCAL_REFERENCE_CYCLE");
 let x:unknown=root;
 for(const encoded of ref.slice(2).split("/")){
  if(!/^(?:[^~]|~[01])*$/.test(encoded))deny("INVALID_LOCAL_POINTER");
  const k=encoded.replace(/~1/g,"/").replace(/~0/g,"~");
  if(!Object.prototype.hasOwnProperty.call(obj(x),k))deny("UNRESOLVED_LOCAL_REFERENCE");
  x=obj(x)[k];
 }
 if(obj(x).$ref)return resolve(root,String(obj(x).$ref),[...trace,ref]);
 return x;
}
function refsValid(root:Dict){
 let nodes=0;
 const visit=(x:unknown)=>{
  if(++nodes>maxNodes)deny("DOCUMENT_COMPLEXITY_LIMIT");
  if(!x||typeof x!=="object")return;
  for(const [k,v] of Object.entries(x)){
   if(k==="$ref")resolve(root,String(v)); else visit(v);
  }
 };
 visit(root);
}
function schemaShape(x:unknown,root:Dict,pointer:string,media:string,status:string|null):Shape {
 const node=obj(x).$ref?obj(resolve(root,String(obj(x).$ref))):obj(x);
 const composition=["allOf","oneOf","anyOf","not"].filter(k=>node[k]!==undefined);
 const required=arr(node.required).filter(s=>typeof s==="string") as string[];
 const nullable=node.nullable===true||arr(node.type).includes("null");
 return {mediaType:media,status,schemaFingerprint:Object.keys(node).length?sha(stable(node)):null,
  type:str(node.type)??(Array.isArray(node.type)?(node.type as string[]).filter(x=>x!=="null").join("|"):null),
  requiredProperties:required,nullable,composition,pointer,description:safeText(node.description)};
}
function effective(value:unknown,defaultReq:unknown,source:string,root:Dict,format:Format):Auth {
 const has=value!==undefined;
 const req=has?value:defaultReq;
 const state:Auth["state"]=!has&&req===undefined?"UNDECLARED":has?"OVERRIDDEN":"INHERITED";
 if(req===undefined)return {state:"UNDECLARED",source,requirements:[]};
 if(!Array.isArray(req))deny("INVALID_SECURITY_DECLARATION");
 if((req as unknown[]).length===0)return {state:"EXPLICIT_NONE",source,requirements:[]};
 const schemes=obj(format==="SWAGGER_2"?root.securityDefinitions:obj(root.components).securitySchemes);
 const requirements:Record<string,string[]>[]=(req as unknown[]).map((item:unknown)=>{
  if(!item||Array.isArray(item)||typeof item!=="object")deny("INVALID_SECURITY_DECLARATION");
  const out:Record<string,string[]>={};
  for(const [key,scopes] of Object.entries(obj(item))){
   if(!Array.isArray(scopes)||scopes.some(s=>typeof s!=="string"))deny("INVALID_SECURITY_DECLARATION");
   if(!(key in schemes))deny("UNDECLARED_SECURITY_SCHEME");
   out[key]=scopes as string[];
  }
  return out;
 });
 return {state,source,requirements};
}
function collectSchemes(root:Dict,format:Format){
 const defs=obj(format==="SWAGGER_2"?root.securityDefinitions:obj(root.components).securitySchemes);
 const schemes:Inventory["schemes"]={};
 for(const key of Object.keys(defs).sort()){
  const value=obj(defs[key]);const type=String(value.type??"unknown");
  schemes[key]={type: type==="basic"?"http-basic":type==="oauth2"?"oauth2":type,
   ...(typeof value.in==="string"?{in:value.in}:{}),
   ...(typeof value.name==="string"?{name:value.name}:{}),
   ...(typeof value.scheme==="string"?{scheme:value.scheme}:{}),
   ...(value.flows?{flows:Object.keys(obj(value.flows)).sort()}:value.flow?{flows:[String(value.flow)]}:{})};
 }
 return schemes;
}
function parameter(x:unknown,root:Dict,pointer:string):Parameter {
 const p=obj(x).$ref?obj(resolve(root,String(obj(x).$ref))):obj(x);
 if(typeof p.name!=="string"||typeof p.in!=="string")deny("INVALID_PARAMETER");
 const shape=obj(p.schema);const t=Object.keys(shape).length?shape:p;
 return {name:String(p.name),in:String(p.in),required:p.required===true||p.in==="path",type:str(t.type),format:str(t.format),
  schemaFingerprint:sha(stable(t)),pointer,constraints:{...(t.enum?{enumCount:arr(t.enum).length}:{}),
   ...(t.minimum!==undefined?{minimum:t.minimum}:{}),...(t.maximum!==undefined?{maximum:t.maximum}:{})}};
}
function shapeList(node:Dict,root:Dict,pointer:string,status:string|null,swagger:boolean):Shape[]{
 if(swagger){
  const schema=node.schema??node.examples;
  return [schemaShape(schema,root,pointer+"/schema",str(node["x-media-type"])??"application/json",status)];
 }
 return Object.keys(obj(node.content)).sort().map(type=>schemaShape(obj(obj(node.content)[type]).schema,root,
 pointer+"/content/"+jsonPointer(type)+"/schema",type,status));
}
function apiInventory(root:Dict,format:Exclude<Format,"POSTMAN_2_1">,content:string):Inventory {
 refsValid(root);
 const paths=obj(root.paths);
 if(!root.paths||Array.isArray(root.paths))deny("MISSING_PATHS");
 const swagger=format==="SWAGGER_2";
 const servers=swagger?(typeof root.host==="string"?arr(root.schemes).length?arr(root.schemes).map(s=>String(s)+"://"+root.host+String(root.basePath??"/")):["https://"+root.host+String(root.basePath??"/")]:[])
   :arr(root.servers).map(x=>str(obj(x).url)).filter((x):x is string=>x!==null);
 const schemes=collectSchemes(root,format),ops:DiscoveredOperation[]=[];
 const ids=new Set<string>(); const warnings=["DECLARED_SPEC_ONLY_NO_RUNTIME_CONFIRMATION"];
 for(const declared of servers){
  // Never dereference declared URLs or silently add them to customer target authorization.
  if(declared.length>2048 || [...declared].some(ch=>ch.charCodeAt(0)<32))deny("UNSAFE_SERVER_DECLARATION");
  try{
   const uri=new URL(declared);
   if(uri.username||uri.password||uri.hash||uri.search)deny("UNSAFE_SERVER_DECLARATION");
   if(uri.protocol!=="https:" || /^(?:localhost|127\.|10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.|169\.254\.|0\.|\[::1\])/i.test(uri.hostname))
    warnings.push("UNTRUSTED_DECLARED_SERVER");
  }catch(e){
   if(e instanceof DiscoveryError)throw e;
   // Relative/variable server templates remain inert and explicitly unknown.
   warnings.push("UNRESOLVED_SERVER_TEMPLATE");
  }
 }
 for(const path of Object.keys(paths).sort()){
  if(!path.startsWith("/")||path.includes(".."))deny("INVALID_PATH_TEMPLATE");
  let item=obj(paths[path]);if(item.$ref)item=obj(resolve(root,String(item.$ref)));
  const inheritedParams=arr(item.parameters);
  for(const method of methods){
   if(item[method]===undefined)continue;
   const info=obj(item[method]);if(!Object.keys(info).length)deny("INVALID_OPERATION");
   if(typeof info.responses!=="object"||!Object.keys(obj(info.responses)).length)deny("MISSING_OPERATION_RESPONSES");
   const ptr="/paths/"+jsonPointer(path)+"/"+method,rawParams=[...inheritedParams,...arr(info.parameters)];
   const params=rawParams.map((x,i)=>parameter(x,root,ptr+"/parameters/"+i));
   const paramMap=new Map<string,Parameter>();
   for(const p of params){const k=p.in+":"+p.name;if(paramMap.has(k))warnings.push("DUPLICATE_PARAMETER");
     paramMap.set(k,p);}
   const opId=str(info.operationId);
   if(opId){if(ids.has(opId))warnings.push("DUPLICATE_OPERATION_ID");ids.add(opId);}
   const defaultSecurity=root.security;
   const auth=effective(info.security,defaultSecurity,ptr+"/security",root,format);
   const operationServers=swagger?servers:arr(info.servers??item.servers).length?
      arr(info.servers??item.servers).map(x=>str(obj(x).url)).filter((x):x is string=>x!==null):servers;
   const requestBodies:Shape[]=swagger?rawParams.filter(x=>obj(x).in==="body").map((x,i)=>
      schemaShape(obj(x).schema,root,ptr+"/parameters/"+i+"/schema",String(arr(info.consumes??root.consumes)[0]??"application/json"),null))
      :shapeList(obj(info.requestBody).$ref?obj(resolve(root,String(obj(info.requestBody).$ref))):obj(info.requestBody),root,ptr+"/requestBody",null,false);
   const responses=Object.keys(obj(info.responses)).sort().flatMap(status=>{
    const node=obj(obj(info.responses)[status]);const r=node.$ref?obj(resolve(root,String(node.$ref))):node;
    return shapeList(r,root,ptr+"/responses/"+jsonPointer(status),status,swagger);
   });
   ops.push({key:method.toUpperCase()+" "+path,method:method.toUpperCase(),path,originalPath:path,
    operationId:opId,summary:safeText(info.summary),description:safeText(info.description),tags:arr(info.tags).filter(s=>typeof s==="string") as string[],
    folder:[],deprecated:info.deprecated===true,pointer:ptr,servers:operationServers,auth,
    parameters:[...paramMap.values()],requestBodies,responses,warnings:[],unresolved:[]});
   if(ops.length>maxOperations)deny("TOO_MANY_OPERATIONS");
  }
 }
 if(format==="OPENAPI_3_1"&&root.webhooks)warnings.push("WEBHOOKS_UNSUPPORTED");
 if(format!=="SWAGGER_2"&&ops.some(o=>obj(obj(paths[o.path])[o.method.toLowerCase()]).callbacks))warnings.push("CALLBACKS_UNSUPPORTED");
 return finalize(format,content,{title:safeText(obj(root.info).title),declaredVersion:str(obj(root.info).version),
   servers,warnings,coverage:warnings.length>1?"PARTIAL":"SUPPORTED_PROFILE"},schemes,ops,content);
}
function postmanInventory(root:Dict,content:string):Inventory {
 const info=obj(root.info);if(info.schema!=="https://schema.getpostman.com/json/collection/v2.1.0/collection.json")deny("UNSUPPORTED_POSTMAN_VERSION");
 if(!Array.isArray(root.item)||typeof info.name!=="string")deny("INVALID_POSTMAN_COLLECTION");
 let count=0;const warnings=["DECLARED_SPEC_ONLY_NO_RUNTIME_CONFIRMATION"],ops:DiscoveredOperation[]=[];
 const schemes:Inventory["schemes"]={};
 const vars=[...arr(root.variable)];if(vars.length)warnings.push("UNRESOLVED_COLLECTION_VARIABLES");
 const authFor=(value:unknown,parent:Auth,pointer:string):Auth=>{
  const x=obj(value);if(value===undefined||x.type==="inherit")return {...parent,state:parent.state==="UNDECLARED"?"UNDECLARED":"INHERITED",source:pointer};
  if(x.type==="noauth")return {state:"EXPLICIT_NONE",source:pointer,requirements:[]};
  if(!x.type)return {state:"UNKNOWN",source:pointer,requirements:[]};
  const type=String(x.type);
  if(!["basic","bearer","apikey","oauth2","jwt"].includes(type)){warnings.push("POSTMAN_AUTH_UNSUPPORTED");return {state:"UNKNOWN",source:pointer,requirements:[]};}
  const key="postman:"+type;schemes[key]={type:type==="apikey"?"apiKey":type==="basic"?"http-basic":type};
  return {state:"OVERRIDDEN",source:pointer,requirements:[{[key]:[]}]};
 };
 const recurse=(items:unknown[],folder:string[],parentAuth:Auth,pointer:string,depth=0)=>{
  if(depth>16)deny("COLLECTION_FOLDER_DEPTH_LIMIT");
  for(let i=0;i<items.length;i++){
   if(++count>3000)deny("COLLECTION_COUNT_LIMIT");
   const item=obj(items[i]),p=pointer+"/"+i; if(!Object.keys(item).length)deny("INVALID_COLLECTION_ITEM");
   if(item.event!==undefined||item.script!==undefined)warnings.push("POSTMAN_SCRIPT_IGNORED");
   const itemName=safeText(item.name)??"Unnamed";
   const auth=authFor(item.auth,parentAuth,p+"/auth");
   if(Array.isArray(item.item)){recurse(item.item,[...folder,itemName],auth,p+"/item",depth+1);continue;}
   const req=obj(item.request);if(!Object.keys(req).length)deny("INVALID_POSTMAN_REQUEST");
   const method=str(req.method)?.toUpperCase();if(!method||!methods.includes(method.toLowerCase()))deny("INVALID_POSTMAN_METHOD");
   const rawUrl=typeof req.url==="string"?req.url:str(obj(req.url).raw)??"";
   const url=obj(req.url);let path="";
   if(Array.isArray(url.path))path="/"+url.path.map(x=>typeof x==="string"?x:String(obj(x).value??"")).join("/");
   else{
    const tail=rawUrl.replace(/^[A-Za-z][A-Za-z0-9+.-]*:\/\/[^/]+/,"").split(/[?#]/)[0];
    path=(tail??"").startsWith("/")?(tail??""):"/"+(tail??"");
   }
   path=path.replace(/:[A-Za-z0-9_]+/g,x=>"{"+x.slice(1)+"}");
   if(!path.startsWith("/")||path.includes("..")||[...path].some(ch=>ch.charCodeAt(0)<32))deny("INVALID_POSTMAN_PATH");
   const unresolved=[...new Set((rawUrl.match(/\{\{[A-Za-z_][\w.-]*\}\}/g)??[]))];
   if(unresolved.length)warnings.push("UNRESOLVED_POSTMAN_VARIABLES");
   const pointerOp=p+"/request";
   const parameters:Parameter[]=[];
   for(const [loc,values] of [["query",url.query],["path",url.variable],["header",req.header]] as const){
    arr(values).forEach((entry,j)=>{
     const node=obj(entry);const name=str(node.key)??str(node.id);
     if(!name)return;
     parameters.push({name,in:loc,required:loc==="path"||node.disabled!==true,type:"string",format:null,
      schemaFingerprint:null,pointer:pointerOp+"/"+loc+"/"+j,constraints:{disabled:node.disabled===true}});
    });
   }
   const body=obj(req.body);
   const requestBodies:Shape[]=Object.keys(body).length?[{mediaType:str(body.options&&obj(body.options).raw)??"unknown",status:null,
    schemaFingerprint:null,type:str(body.mode),requiredProperties:[],nullable:false,composition:[],pointer:pointerOp+"/body",description:"Body declaration only; contents and scripts not executed"}]:[];
   const responses:Shape[]=arr(item.response).map((v,j)=>({mediaType:str(obj(v).header&&obj(arr(obj(v).header)[0]).value)??"unknown",
    status:String(obj(v).code??"unknown"),schemaFingerprint:null,type:null,requiredProperties:[],nullable:false,
    composition:[],pointer:p+"/response/"+j,description:safeText(obj(v).name)}));
   const opAuth=authFor(req.auth,auth,pointerOp+"/auth");
   const key=method+" "+path;
   if(ops.some(x=>x.key===key))warnings.push("DUPLICATE_POSTMAN_OPERATION");
   ops.push({key,method:method as string,path,originalPath:path,operationId:null,summary:itemName,description:safeText(obj(req.description).content??req.description),
    tags:[],folder,deprecated:item.disabled===true,pointer:pointerOp,servers:[],auth:opAuth,parameters,
    requestBodies,responses,warnings:item.disabled===true?["DISABLED_REQUEST"]:[],unresolved});
   if(ops.length>maxOperations)deny("TOO_MANY_OPERATIONS");
  }
 };
 const rootAuth=authFor(root.auth,{state:"UNDECLARED",source:"/auth",requirements:[]},"/auth");
 recurse(arr(root.item),[],rootAuth,"/item");
 if(!ops.length)deny("NO_DISCOVERABLE_OPERATIONS");
 // Postman entries may repeat a path/method; duplicate entries are tracked in warnings, not overwritten.
 const canonicalOps=ops.map((x,i)=>({...x,key:ops.filter(y=>y.key===x.key).length>1?x.key+" #"+i:x.key}));
 // Projection deliberately null: Postman collection cannot safely be assumed equivalent to formal OpenAPI
 // for existing assessment rules; users may inspect/diff but cannot claim SPEC_ONLY assessment compatibility.
 return finalize("POSTMAN_2_1",content,{title:safeText(info.name),declaredVersion:str(info.version),servers:[],
  warnings:[...new Set(warnings)],coverage:"PARTIAL"},schemes,canonicalOps,null);
}
function finalize(format:Format,content:string,metadata:Inventory["metadata"],schemes:Inventory["schemes"],operations:DiscoveredOperation[],assessmentSource:string|null):Inventory {
 const normalizedOperations=[...operations].sort((a,b)=>a.key.localeCompare(b.key));
 const canonical={format,normalizationVersion:"phase02-v1",metadata:{title:metadata.title,declaredVersion:metadata.declaredVersion,servers:[...metadata.servers].sort()},schemes,operations:normalizedOperations.map(x=>({
  ...x,pointer:undefined,description:x.description,parameters:x.parameters.map(p=>({...p,pointer:undefined})),
  requestBodies:x.requestBodies.map(s=>({...s,pointer:undefined})),responses:x.responses.map(s=>({...s,pointer:undefined}))
 }))};
 return {format,normalizationVersion:"phase02-v1",rawFingerprint:sha(content),normalizedFingerprint:sha(stable(canonical)),
  metadata,schemes,operations:normalizedOperations,assessmentSource};
}
export async function importOfflineDocument(content:string):Promise<Inventory> {
 const {root,format}=secureParse(content);
 if(format==="POSTMAN_2_1")return postmanInventory(root,content);
 refsValid(root);
 if(format==="OPENAPI_3_1"||format==="SWAGGER_2")await parseAndValidateSpec(content);
 else {
  const check=await new Validator().validate(root);
  if(!check.valid)deny("OPENAPI_SCHEMA_INVALID");
 }
 const result=apiInventory(root,format,content);
 if(format==="OPENAPI_3_0") {
  // The legacy Phase 0 assessment engine is not 3.0-aware. Offline inventory remains importable,
  // but its analysis eligibility stays false rather than silently coercing 3.0 semantics to 3.1.
  return {...result,assessmentSource:null};
 }
 return result;
}
export type StructuralDiff={from:string;to:string;added:string[];removed:string[];changed:Array<{key:string;fields:string[];possibleBreaking:boolean;fromPointer:string;toPointer:string}>;metadataChanges:string[];reviewRequired:true};
export function compareInventory(from:Inventory,to:Inventory):StructuralDiff {
 const before=new Map(from.operations.map(x=>[x.key,x])),after=new Map(to.operations.map(x=>[x.key,x]));
 const added=[...after.keys()].filter(k=>!before.has(k)).sort(),removed=[...before.keys()].filter(k=>!after.has(k)).sort(),changed:StructuralDiff["changed"]=[];
 const fields=["parameters","requestBodies","responses","auth","deprecated","servers","tags","description"] as const;
 for(const [key,a] of before){
  const b=after.get(key);if(!b)continue;
  const modified=fields.filter(f=>stable(a[f])!==stable(b[f]));
  if(modified.length)changed.push({key,fields:modified,possibleBreaking:modified.some(x=>["parameters","requestBodies","responses","auth"].includes(x)),fromPointer:a.pointer,toPointer:b.pointer});
 }
 const metadataChanges:string[]=[];
 if(stable(from.metadata.servers)!==stable(to.metadata.servers))metadataChanges.push("declaredServers");
 if(stable(from.schemes)!==stable(to.schemes))metadataChanges.push("securitySchemes");
 return {from:from.normalizedFingerprint,to:to.normalizedFingerprint,added,removed,changed:changed.sort((a,b)=>a.key.localeCompare(b.key)),metadataChanges,reviewRequired:true};
}
