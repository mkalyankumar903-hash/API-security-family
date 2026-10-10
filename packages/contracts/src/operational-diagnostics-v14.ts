/** Phase14: allowlisted, bounded synthetic diagnostics. No arbitrary Error or payload serialization. */
export type DiagnosticKind="HTTP_REJECTED"|"HTTP_COMPLETED"|"ASSESSMENT_ADMISSION"|"QUEUE_CLAIM"|"LEASE_RENEWAL"|"WORKER_RETRY"|"WORKER_TERMINAL"|"DB_CONTENTION"|"RESOURCE_REJECTED"|"REPORT_RENDER"|"REPORT_FINALIZED"|"METER_RESERVATION"|"METER_SETTLEMENT"|"METER_EXPIRY"|"METER_CORRECTION"|"METER_RECONCILIATION"|"METER_ENTITLEMENT"|"ASSESSMENT_TRANSITION"|"WORKER_SHUTDOWN"|"QA_DELIVERY";
export type DiagnosticClass="AUTH"|"VALIDATION"|"CAPACITY"|"TIMEOUT"|"CONFLICT"|"INTERNAL"|"OK"|"STALE"|"RETRY"|"EXHAUSTED";
export type DiagnosticInput={
 kind:DiagnosticKind;classification:DiagnosticClass;statusCode:number;durationMs?:number;
 requestId?:unknown;attempt?:number;queueWaitMs?:number;feature?:unknown;state?:unknown;
};
const safeId=/^[a-f0-9-]{1,64}$/i;
const FEATURES=new Set(["IMMUTABLE_REPORT_OBSERVED","OFFLINE_API_ASSESSMENT_COMPLETED",
 "SIGNED_GOVERNED_PT_CONSUMED"]);
const STATES=new Set(["RESERVED","SETTLED","EXPIRED","RELEASED","RETRY","DEAD_LETTER",
 "CLAIMED","ACKED","MATCHED","MISMATCH","PENDING_EXTERNAL_AUTHORITY",
 "COMPLETED","FAILED","CANCELLED","LOST","QUARANTINED","ISSUED","REVOKED",
 "PENDING","STALE"]);
const KINDS=new Set<DiagnosticKind>(["HTTP_REJECTED","HTTP_COMPLETED","ASSESSMENT_ADMISSION",
 "QUEUE_CLAIM","LEASE_RENEWAL","WORKER_RETRY","WORKER_TERMINAL","DB_CONTENTION",
 "RESOURCE_REJECTED","REPORT_RENDER","REPORT_FINALIZED","METER_RESERVATION","METER_SETTLEMENT",
 "METER_EXPIRY","METER_CORRECTION","METER_RECONCILIATION","METER_ENTITLEMENT",
 "ASSESSMENT_TRANSITION","WORKER_SHUTDOWN","QA_DELIVERY"]);
const CLASSES=new Set<DiagnosticClass>(["AUTH","VALIDATION","CAPACITY","TIMEOUT","CONFLICT",
 "INTERNAL","OK","STALE","RETRY","EXHAUSTED"]);
function bounded(value:unknown,max:number):number|null {
 return typeof value==="number"&&Number.isFinite(value)&&value>=0
  ?Math.min(max,Math.round(value*100)/100):null;
}
/** Never spread user input. Values not in this exact allowlist are not observable. */
export function makeDiagnostic(input:DiagnosticInput){
 return {
  schemaVersion:"api-family-diagnostic-v1" as const,
  kind:KINDS.has(input.kind)?input.kind:"RESOURCE_REJECTED" as const,
  classification:CLASSES.has(input.classification)?input.classification:"INTERNAL" as const,
  statusCode:Number.isInteger(input.statusCode)&&input.statusCode>=100&&input.statusCode<=599?input.statusCode:500,
  requestId:typeof input.requestId==="string"&&safeId.test(input.requestId)?input.requestId:null,
  durationMs:bounded(input.durationMs,3600000),
  attempt:bounded(input.attempt,100),
  queueWaitMs:bounded(input.queueWaitMs,3600000),
  feature:typeof input.feature==="string"&&FEATURES.has(input.feature)?input.feature:null,
  state:typeof input.state==="string"&&STATES.has(input.state)?input.state:null
 };
}
/** Local/CI output only. Never enable telemetry or a privileged read endpoint. */
export function emitDiagnostic(input:DiagnosticInput):void{
 if(process.env.NODE_ENV!=="test"||process.env.SYNTHETIC_AUTH_ENABLED!=="true"||process.env.API_FAMILY_DIAGNOSTICS!=="true")return;
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
