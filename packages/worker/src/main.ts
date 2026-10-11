import { processOneJob } from "./index.js";
import { closeDatabase } from "../../database/src/index.js";
import {emitDiagnostic} from "../../contracts/src/operational-diagnostics-v14.js";
if (process.env.NODE_ENV === "production") throw new Error("HOST_AUTHORITY_NOT_CONFIGURED_PRODUCTION_FAIL_CLOSED");
if(!process.env.WORKER_DATABASE_URL||!process.env.DATABASE_URL)
 throw new Error("ISOLATED_WORKER_DATABASE_CONFIGURATION_REQUIRED");
const stopping=new AbortController();
const testOnly=process.env.NODE_ENV==="test"&&process.env.SYNTHETIC_AUTH_ENABLED==="true"&&
 process.env.GITHUB_ACTIONS==="true";
const drainMs=testOnly&&process.env.PHASE14_TEST_SHUTDOWN_MS==="450"?450:5000;
let deadline:ReturnType<typeof setTimeout>|undefined;
for(const signal of ["SIGTERM","SIGINT"] as const){
 process.on(signal,()=>{
  if(stopping.signal.aborted)return;
  stopping.abort();
  emitDiagnostic({kind:"WORKER_SHUTDOWN",classification:"RETRY",statusCode:202,state:"PENDING"});
  // Process death closes sockets, leaves committed evidence untouched, and
  // preserves generation-fenced DB leases for a later authorized worker.
  deadline=setTimeout(()=>{
   process.stderr.write("PHASE14_WORKER_DRAIN_DEADLINE_EXPIRED\n");
   emitDiagnostic({kind:"WORKER_SHUTDOWN",classification:"EXHAUSTED",statusCode:503,state:"FAILED"});
   process.exit(75);
  },drainMs);
 });
}
try{
 if(process.env.NODE_ENV==="test")process.send?.({kind:"READY"});
 while(!stopping.signal.aborted){
  const didWork=await processOneJob({signal:stopping.signal}).catch((error:unknown)=>{
   console.error("worker error",error instanceof Error?error.name:"unknown");
   return false;
  });
  if(!didWork&&!stopping.signal.aborted){
   await new Promise<void>(resolve=>{
    const onAbort=()=>{clearTimeout(timer);resolve();};
    const timer=setTimeout(()=>{
     stopping.signal.removeEventListener("abort",onAbort);resolve();
    },300);
    stopping.signal.addEventListener("abort",onAbort,{once:true});
   });
  }
 }
}finally{
 // The deadline is deliberately still active while DB cleanup is attempted.
 await closeDatabase();
 if(deadline)clearTimeout(deadline);
}
