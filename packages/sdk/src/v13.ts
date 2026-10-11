/** Phase13 read-only public developer SDK. No token minting or tenant override. */
export type CommercialSummary={
 schemaVersion:"api-family-commercial-v13";tenantContext:string;hostAuthority:string;
 feature:string;meterUnit:string;billable:false;monthStart:string;
 entitlement:{id:string;revision:number;state:"ISSUED"|"REVOKED";expiresAt:string;syntheticOnly:true}|null;
 quota:number;consumed:number;reserved:number;remaining:number;decision:string;
};
/** Never reflect arbitrary upstream error values: an attacker could encode a secret as UPPER_CASE. */
const PUBLIC_ERROR_CODES=new Set([
 "UNAUTHORIZED","PERMISSION_DENIED","NOT_FOUND","OVERLOADED","QUOTA_EXCEEDED",
 "QUEUE_TENANT_CAPACITY_EXCEEDED","HOST_AUTHORITY_NOT_CONFIGURED","HOST_UNAVAILABLE",
 "INVALID_ID","INVALID_IDEMPOTENCY_KEY","INVALID_PAGINATION","INVALID_QUANTITY",
 "INVALID_QUERY","INVALID_RESERVATION_TTL","INVALID_USAGE_CORRECTION",
 "ENTITLEMENT_UNAVAILABLE","ENTITLEMENT_REVISION_CONFLICT","SOURCE_ALREADY_ACCOUNTED",
 "SOURCE_FINGERPRINT_OR_ENTITLEMENT_REVISION_MISMATCH","SOURCE_NOT_SUCCESSFUL",
 "USAGE_SOURCE_NOT_FOUND","EVENT_ID_REUSE_CONFLICT","CORRECTION_ID_REUSE_CONFLICT",
 "RESERVATION_ALREADY_CLOSED","RESERVATION_EXPIRED","RESERVATION_NOT_FOUND",
 "SNAPSHOT_REVISION_CONFLICT","SNAPSHOT_STALE_REVISION","SNAPSHOT_TENANT_MISMATCH",
 "OFFLINE_TERMINAL_EVIDENCE_MISSING","IMMUTABLE_REPORT_NOT_FOUND",
 "SIGNED_GOVERNED_PT_EVIDENCE_MISSING","SIGNED_PT_CONSUMED_SYNTHETIC_EVALUATION_NOT_FOUND",
 "SIGNED_PT_SCOPE_OR_TENANT_PROVENANCE_MISMATCH","SIGNED_PT_STAGES_NOT_COMPLETED",
 "UNSUPPORTED_FEATURE_OR_VERSION","ISOLATED_SYNTHETIC_ONLY",
 "IDEMPOTENCY_CONFLICT","SYNTHETIC_PROJECTION_ONLY"
]);
export class V13ClientError extends Error{
 constructor(readonly status:number,readonly code:string){super(code);}
}
export type V13ClientOptions={
 baseUrl:string;accessToken:()=>string|Promise<string>;fetcher?:typeof fetch;timeoutMs?:number;maxRetries?:0|1|2;
};
const isObject=(v:unknown):v is Record<string,unknown>=>
 typeof v==="object"&&v!==null&&!Array.isArray(v);
const boundedStr=(v:unknown,max=256):v is string=>typeof v==="string"&&v.length<=max;
const whole=(v:unknown)=>typeof v==="number"&&Number.isSafeInteger(v)&&v>=0;
function requireShape(ok:boolean):void{
 if(!ok)throw new V13ClientError(200,"INVALID_RESPONSE");
}
function validateSummary(value:unknown):value is CommercialSummary{
 if(!isObject(value))return false;
 if(value.schemaVersion!=="api-family-commercial-v13"||
  value.hostAuthority!=="HOST_AUTHORITY_NOT_CONFIGURED"||
  value.billable!==false||!boundedStr(value.tenantContext)||
  !boundedStr(value.feature)||!boundedStr(value.meterUnit)||
  !(boundedStr(value.monthStart,40)&& /^\d{4}-\d{2}-\d{2}(?:T00:00:00\.000Z)?$/.test(value.monthStart))||
  !boundedStr(value.decision,300))return false;
 for(const k of ["quota","consumed","reserved","remaining"]){
  if(!whole(value[k]))return false;
 }
 if(value.entitlement!==null){
  if(!isObject(value.entitlement)||!boundedStr(value.entitlement.id,80)||
   !whole(value.entitlement.revision)||
   !["ISSUED","REVOKED"].includes(String(value.entitlement.state))||
   !boundedStr(value.entitlement.expiresAt,80)||
   value.entitlement.syntheticOnly!==true)return false;
 }
 return true;
}
function validateV13Read(path:string,payload:unknown):void{
 if(path==="/v13/capabilities"){
  requireShape(isObject(payload)&&payload.schemaVersion==="api-family-commercial-v13"&&
   payload.hostAuthority==="HOST_AUTHORITY_NOT_CONFIGURED"&&payload.scanningAuthority===false&&
   Array.isArray(payload.meterDefinitions)&&payload.meterDefinitions.length<=20);
 }else if(path==="/v13/usage/summary"){
  requireShape(validateSummary(payload));
 }else if(path==="/v13/entitlements"){
  requireShape(isObject(payload)&&validateSummary(payload.projection));
 }else if(path.startsWith("/v13/decisions?")){
  requireShape(isObject(payload)&&payload.allowed===false&&
   payload.code==="HOST_AUTHORITY_NOT_CONFIGURED"&&
   typeof payload.syntheticProjectionWouldAllow==="boolean");
 }else if(["/v13/usage/events?","/v13/usage/corrections?","/v13/reservations?","/v13/reconciliations?"]
  .some(prefix=>path.startsWith(prefix))){
  requireShape(Array.isArray(payload)&&payload.length<=100&&payload.every((row:unknown)=>{
   if(!isObject(row)||!boundedStr(row.id,80))return false;
   if(path.startsWith("/v13/usage/events?"))
    return boundedStr(row.sourceReportId,80)&&whole(row.units);
   if(path.startsWith("/v13/usage/corrections?"))
    return boundedStr(row.sourceUsageId,80)&&typeof row.unitDelta==="number"&&
     Number.isSafeInteger(row.unitDelta)&&boundedStr(row.reason,256);
   if(path.startsWith("/v13/reservations?"))
    return boundedStr(row.state,60)&&whole(row.units);
   return boundedStr(row.state,60)&&whole(row.localUnits);
  }));
 }
}
export class V13Client{
 private readonly request:typeof fetch;
 private readonly base:string;
 private readonly timeoutMs:number;
 constructor(private readonly config:V13ClientOptions){
  let url:URL;
  try{url=new URL(config.baseUrl);}catch{throw new Error("INVALID_API_ORIGIN");}
  if(config.maxRetries!==undefined&&![0,1,2].includes(config.maxRetries))throw new Error("INVALID_RETRY_BUDGET");
  if(!["https:","http:"].includes(url.protocol)||url.username||url.password||url.search||url.hash||url.pathname!=="/"||
   (url.protocol==="http:"&&!["127.0.0.1","localhost","[::1]"].includes(url.hostname)))
   throw new Error("INVALID_API_ORIGIN");
  if(!Number.isSafeInteger(config.timeoutMs??10000)||(config.timeoutMs??10000)<100||(config.timeoutMs??10000)>60000)
   throw new Error("INVALID_TIMEOUT");
  this.base=url.origin;this.timeoutMs=config.timeoutMs??10000;
  // Window.fetch is a WebIDL operation: preserve the global receiver when passed to a class.
  this.request=(config.fetcher??globalThis.fetch).bind(globalThis);
 }
 /** Also bound custom fetch mocks and credential providers that ignore AbortSignal. */
 private async abortable<T>(work:Promise<T>,signal:AbortSignal,caller?:AbortSignal):Promise<T>{
  if(signal.aborted)throw new V13ClientError(0,caller?.aborted?"ABORTED":"TRANSPORT_OR_TIMEOUT");
  let onAbort:()=>void=()=>{};
  const aborted=new Promise<never>((_,reject)=>{
   onAbort=()=>reject(new V13ClientError(0,caller?.aborted?"ABORTED":"TRANSPORT_OR_TIMEOUT"));
   signal.addEventListener("abort",onAbort,{once:true});
  });
  try{return await Promise.race([work,aborted]);}
  finally{signal.removeEventListener("abort",onAbort);}
 }
 /** Bound every response body before parsing: a hostile adapter cannot force unbounded JSON buffering. */
 private async readJson(response:Response,signal:AbortSignal,caller?:AbortSignal):Promise<unknown>{
  const length=response.headers.get("content-length");
  if(length!==null&&(!/^\d+$/.test(length)||Number(length)>1048576))throw new V13ClientError(response.status,"RESPONSE_SIZE_LIMIT");
  const type=response.headers.get("content-type")?.toLowerCase()??"";
  const mediaType=type.split(";")[0]?.trim()??"";
  if(mediaType!==""&&mediaType!=="application/json"&&
   !(mediaType.startsWith("application/")&&mediaType.endsWith("+json")))
   throw new V13ClientError(response.status,"INVALID_CONTENT_TYPE");
  const reader=response.body?.getReader();
  if(!reader)throw new V13ClientError(response.status,"INVALID_RESPONSE");
  const parts:Uint8Array[]=[];
  let size=0;
  try{
   for(;;){
    const {done,value}=await this.abortable(reader.read(),signal,caller);
    if(done)break;
    size+=value.byteLength;
    if(size>1048576){void reader.cancel().catch(()=>undefined);throw new V13ClientError(response.status,"RESPONSE_SIZE_LIMIT");}
    parts.push(value);
   }
   const buffer=new Uint8Array(size);
   let offset=0;
   for(const chunk of parts){buffer.set(chunk,offset);offset+=chunk.byteLength;}
   return JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(buffer)) as unknown;
  }catch(error){
   if(error instanceof V13ClientError)throw error;
   throw new V13ClientError(response.status,"INVALID_RESPONSE");
  }finally{if(signal.aborted)void reader.cancel().catch(()=>undefined);try{reader.releaseLock();}catch{/* pending stream reader remains aborted */}}
 }
 private async get<T>(path:string,signal?:AbortSignal):Promise<T>{
  if(signal?.aborted)throw new V13ClientError(0,"ABORTED");
  // Explicit ref-counted timer keeps Node CLI alive even when a custom provider or stream stalls.
  const deadline=new AbortController();
  const timer=setTimeout(()=>deadline.abort(),this.timeoutMs);
  const combined=AbortSignal.any([deadline.signal,...(signal?[signal]:[])]);
  try{
  let token:string;
  try{token=await this.abortable(Promise.resolve().then(()=>this.config.accessToken()),combined,signal);}
  catch(error){if(error instanceof V13ClientError)throw error;throw new V13ClientError(401,"AUTH_PROVIDER_FAILED");}
  if(typeof token!=="string"||token.length===0||token.length>4096||/[^\x21-\x7e]/.test(token))
   throw new V13ClientError(401,"MISSING_AUTHENTICATION");
  let response:Response|undefined;
  for(let attempt=0;attempt<=(this.config.maxRetries??0);attempt++){
   if(combined.aborted)throw new V13ClientError(0,signal?.aborted?"ABORTED":"TRANSPORT_OR_TIMEOUT");
   try{response=await this.abortable(this.request(this.base+path,{
    method:"GET",headers:{authorization:"Bearer "+token,accept:"application/json"},
    cache:"no-store",signal:combined,redirect:"error"}),combined,signal);
   }catch{
    if(signal?.aborted)throw new V13ClientError(0,"ABORTED");
    if(attempt===(this.config.maxRetries??0)||combined.aborted)throw new V13ClientError(0,"TRANSPORT_OR_TIMEOUT");
    await this.backoff(attempt,combined,signal);
    continue;
   }
   if([429,502,503,504].includes(response.status)&&attempt<(this.config.maxRetries??0)){
    await response.body?.cancel().catch(()=>undefined);
    await this.backoff(attempt,combined,signal);
    continue;
   }
   break;
  }
  if(!response)throw new V13ClientError(0,"TRANSPORT_OR_TIMEOUT");
  const payload=await this.readJson(response,combined,signal);
  if(!response.ok){
   const code=typeof payload==="object"&&payload!==null&&"error" in payload&&
    typeof payload.error==="string"&&PUBLIC_ERROR_CODES.has(payload.error)?payload.error:"API_ERROR";
   throw new V13ClientError(response.status,code);
  }
  if(payload===null||typeof payload!=="object")throw new V13ClientError(response.status,"INVALID_RESPONSE");
  if(!Array.isArray(payload)&&"schemaVersion" in payload&&
    payload.schemaVersion!=="api-family-commercial-v13")
   throw new V13ClientError(response.status,"SCHEMA_VERSION_MISMATCH");
  validateV13Read(path,payload);
  return payload as T;
  }finally{clearTimeout(timer);}
 }
 private async backoff(attempt:number,signal:AbortSignal,caller?:AbortSignal):Promise<void>{
  await new Promise<void>((resolve,reject)=>{
   if(signal.aborted){reject(new V13ClientError(0,caller?.aborted?"ABORTED":"TRANSPORT_OR_TIMEOUT"));return;}
   const onAbort=()=>{clearTimeout(timer);reject(new V13ClientError(0,caller?.aborted?"ABORTED":"TRANSPORT_OR_TIMEOUT"));};
   const timer=setTimeout(()=>{signal.removeEventListener("abort",onAbort);resolve();},50*(attempt+1));
   signal.addEventListener("abort",onAbort,{once:true});
  });
 }
 capabilities(signal?:AbortSignal){return this.get<{schemaVersion:string;hostAuthority:string;meterDefinitions:unknown[];scanningAuthority:false}>("/v13/capabilities",signal);}
 summary(signal?:AbortSignal){return this.get<CommercialSummary>("/v13/usage/summary",signal);}
 entitlements(signal?:AbortSignal){return this.get<{projection:CommercialSummary}>("/v13/entitlements",signal);}
 decision(quantity=1,signal?:AbortSignal){
  if(!Number.isSafeInteger(quantity)||quantity<1||quantity>1000000)throw new Error("INVALID_QUANTITY");
  return this.get<{allowed:false;code:string;syntheticProjectionWouldAllow:boolean}>("/v13/decisions?quantity="+quantity,signal);
 }
 private paginate<T>(path:string,limit=25,offset=0,signal?:AbortSignal){
  if(!Number.isSafeInteger(limit)||limit<1||limit>100||!Number.isSafeInteger(offset)||offset<0||offset>100000)
   throw new Error("INVALID_PAGINATION");
  return this.get<T[]>(path+"?limit="+limit+"&offset="+offset,signal);
 }
 usage(limit=25,offset=0,signal?:AbortSignal){return this.paginate<{id:string;units:number;sourceReportId:string}>("/v13/usage/events",limit,offset,signal);}
 corrections(limit=25,offset=0,signal?:AbortSignal){return this.paginate<{id:string;sourceUsageId:string;unitDelta:number;reason:string}>("/v13/usage/corrections",limit,offset,signal);}
 reservations(limit=25,offset=0,signal?:AbortSignal){return this.paginate<{id:string;state:string;units:number}>("/v13/reservations",limit,offset,signal);}
 reconciliations(limit=25,offset=0,signal?:AbortSignal){return this.paginate<{id:string;state:string;localUnits:number}>("/v13/reconciliations",limit,offset,signal);}
}
