import { processOneJob } from "./index.js";
import { closeDatabase } from "../../database/src/index.js";
if (process.env.NODE_ENV === "production") throw new Error("HOST_AUTHORITY_NOT_CONFIGURED_PRODUCTION_FAIL_CLOSED");
if(!process.env.WORKER_DATABASE_URL||!process.env.DATABASE_URL)
  throw new Error("ISOLATED_WORKER_DATABASE_CONFIGURATION_REQUIRED");
const stopping=new AbortController();
for(const signal of ["SIGTERM","SIGINT"] as const){
 process.on(signal,()=>stopping.abort());
}
try{
 while(!stopping.signal.aborted){
  const didWork=await processOneJob({signal:stopping.signal}).catch((error:unknown)=>{
   console.error("worker error",error instanceof Error?error.name:"unknown");
   return false;
  });
  if(!didWork&&!stopping.signal.aborted){
   await new Promise<void>(resolve=>{
    const timer=setTimeout(resolve,300);
    stopping.signal.addEventListener("abort",()=>{
     clearTimeout(timer);resolve();
    },{once:true});
   });
  }
 }
}finally{
 await closeDatabase();
}
