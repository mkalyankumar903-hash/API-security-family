/** Phase13 read-only public developer SDK. No token minting or tenant override. */
export type CommercialSummary={
 schemaVersion:"api-family-commercial-v13";tenantContext:string;hostAuthority:string;
 feature:string;meterUnit:string;billable:false;monthStart:string;
 entitlement:{id:string;revision:number;state:"ISSUED"|"REVOKED";expiresAt:string;syntheticOnly:true}|null;
 quota:number;consumed:number;reserved:number;remaining:number;decision:string;
};
export class V13ClientError extends Error{
 constructor(readonly status:number,readonly code:string){super(code);}
}
export type V13ClientOptions={
 baseUrl:string;accessToken:()=>string|Promise<string>;fetcher?:typeof fetch;timeoutMs?:number;
};
export class V13Client{
 private readonly request:typeof fetch;
 private readonly base:string;
 private readonly timeoutMs:number;
 constructor(private readonly config:V13ClientOptions){
  const url=new URL(config.baseUrl);
  if(!["https:","http:"].includes(url.protocol)||url.username||url.password||url.search||url.hash||
   (url.protocol==="http:"&&!["127.0.0.1","localhost","[::1]"].includes(url.hostname)))
   throw new Error("INVALID_API_ORIGIN");
  if(!Number.isSafeInteger(config.timeoutMs??10000)||(config.timeoutMs??10000)<100||(config.timeoutMs??10000)>60000)
   throw new Error("INVALID_TIMEOUT");
  this.base=url.origin;this.timeoutMs=config.timeoutMs??10000;
  // Window.fetch is a WebIDL operation: preserve the global receiver when passed to a class.
  this.request=(config.fetcher??globalThis.fetch).bind(globalThis);
 }
 private async get<T>(path:string,signal?:AbortSignal):Promise<T>{
  const token=await this.config.accessToken();
  if(!token||/[\r\n]/.test(token))throw new V13ClientError(401,"MISSING_AUTHENTICATION");
  const combined=AbortSignal.any([AbortSignal.timeout(this.timeoutMs),...(signal?[signal]:[])]);
  let response:Response;
  try{response=await this.request(this.base+path,{
   method:"GET",headers:{authorization:"Bearer "+token,accept:"application/json"},
   cache:"no-store",signal:combined,redirect:"error"});
  }catch{throw new V13ClientError(0,"TRANSPORT_OR_TIMEOUT");}
  let payload:unknown;
  try{payload=await response.json() as unknown;}catch{throw new V13ClientError(response.status,"INVALID_RESPONSE");}
  if(!response.ok){
   const code=typeof payload==="object"&&payload!==null&&"error" in payload&&
    typeof payload.error==="string"?payload.error:"API_ERROR";
   throw new V13ClientError(response.status,code);
  }
  return payload as T;
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
 reservations(limit=25,offset=0,signal?:AbortSignal){return this.paginate<{id:string;state:string;units:number}>("/v13/reservations",limit,offset,signal);}
 reconciliations(limit=25,offset=0,signal?:AbortSignal){return this.paginate<{id:string;state:string;localUnits:number}>("/v13/reconciliations",limit,offset,signal);}
}
