/** Phase14: allowlisted, bounded synthetic diagnostics. No arbitrary Error or payload serialization. */
export type DiagnosticKind="HTTP_REJECTED"|"HTTP_COMPLETED"|"WORKER_RETRY"|"DB_CONTENTION"|"RESOURCE_REJECTED";
export type DiagnosticClass="AUTH"|"VALIDATION"|"CAPACITY"|"TIMEOUT"|"CONFLICT"|"INTERNAL"|"OK";
export type DiagnosticInput={
 kind:DiagnosticKind;classification:DiagnosticClass;statusCode:number;durationMs?:number;
 requestId?:unknown;attempt?:number;queueWaitMs?:number;
};
const safeId=/^[a-f0-9-]{1,64}$/i;
function bounded(value:unknown,max:number):number|null {
 return typeof value==="number"&&Number.isFinite(value)&&value>=0
  ?Math.min(max,Math.round(value*100)/100):null;
}
/** Never spread user input. Values not in this exact allowlist are not observable. */
export function makeDiagnostic(input:DiagnosticInput){
 return {
  schemaVersion:"api-family-diagnostic-v1" as const,
  kind:input.kind,
  classification:input.classification,
  statusCode:Number.isInteger(input.statusCode)&&input.statusCode>=100&&input.statusCode<=599?input.statusCode:500,
  requestId:typeof input.requestId==="string"&&safeId.test(input.requestId)?input.requestId:null,
  durationMs:bounded(input.durationMs,3600000),
  attempt:bounded(input.attempt,100),
  queueWaitMs:bounded(input.queueWaitMs,3600000)
 };
}
/** Local/CI output only. Never enable telemetry or a privileged read endpoint. */
export function emitDiagnostic(input:DiagnosticInput):void{
 if(process.env.NODE_ENV==="production"||process.env.API_FAMILY_DIAGNOSTICS!=="true")return;
 process.stderr.write("API_FAMILY_DIAGNOSTIC "+JSON.stringify(makeDiagnostic(input))+"\n");
}
export function classifyHttp(status:number):DiagnosticClass{
 if(status===401||status===403)return "AUTH";
 if(status===400||status===413||status===415||status===422)return "VALIDATION";
 if(status===429||status===503)return "CAPACITY";
 if(status===408||status===504)return "TIMEOUT";
 if(status===409)return "CONFLICT";
 return status>=500?"INTERNAL":"OK";
}
