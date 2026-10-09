import {Worker} from "node:worker_threads";
import {DiscoveryError,type Inventory} from "./index.js";
const MAX_CONCURRENT_IMPORTS=4,MAX_PARSE_MS=5000;
let active=0;
/** Strict per-import worker isolation: no URL fetching, hard wallclock termination and V8 heap ceilings. */
export async function importOfflineIsolated(content:string):Promise<Inventory>{
 if(active>=MAX_CONCURRENT_IMPORTS)throw new DiscoveryError("IMPORT_CONCURRENCY_LIMIT");
 if(Buffer.byteLength(content,"utf8")>1048576)throw new DiscoveryError("DOCUMENT_SIZE_LIMIT");
 active++;
 try{
  return await new Promise<Inventory>((resolve,reject)=>{
   const thread=new Worker(new URL("./worker-entry.mjs",import.meta.url),{
     workerData:{content},execArgv:[],
     resourceLimits:{maxOldGenerationSizeMb:128,maxYoungGenerationSizeMb:32,stackSizeMb:4}
   });
   let done=false;
   const finish=(value:Inventory|null,err:Error|null)=>{
    if(done)return;done=true;clearTimeout(timer);
    void thread.terminate();
    if(err)reject(err);else if(value)resolve(value);else reject(new DiscoveryError("IMPORT_RUNTIME_FAILURE"));
   };
   const timer=setTimeout(()=>finish(null,new DiscoveryError("IMPORT_TIME_LIMIT")),MAX_PARSE_MS);
   thread.once("message",(msg:{ok:boolean;inventory?:Inventory;code?:string;blockedAttempts?:number})=>{
    if((msg.blockedAttempts??0)>0)finish(null,new DiscoveryError("OFFLINE_NETWORK_EGRESS_DENIED"));
    else if(msg.ok&&msg.inventory)finish(msg.inventory,null);
    else finish(null,new DiscoveryError(msg.code??"DOCUMENT_VALIDATION_FAILED"));
   });
   thread.once("error",()=>finish(null,new DiscoveryError("IMPORT_RUNTIME_FAILURE")));
   thread.once("exit",code=>{if(code!==0)finish(null,new DiscoveryError("IMPORT_WORKER_TERMINATED"));});
  });
 }finally{active--;}
}
