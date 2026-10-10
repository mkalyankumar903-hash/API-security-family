/** Dedicated GitHub Actions child process: the parent may SIGKILL only this process. */
import {reserveObservedReport,settleObservedReport,closeReservation} from "../../packages/service/src/phase13.js";
import {enqueueQaDelivery,claimQaDelivery,consumeQaSink,ackQaDelivery} from "../../packages/service/src/phase13-delivery-qa.js";
import {phase13TestFaultBarrier,closeDatabase} from "../../packages/database/src/index.js";
const [kind,tenant,source,key]=process.argv.slice(2);
if(process.env.NODE_ENV!=="test"||process.env.SYNTHETIC_AUTH_ENABLED!=="true"||!process.send)
 throw new Error("CHILD_TEST_AUTHORITY_REQUIRED");
async function run(){
 if(kind==="reserve")return reserveObservedReport(tenant!,source!,key!);
 if(kind==="settle")return settleObservedReport(tenant!,source!);
 if(kind==="close")return closeReservation(tenant!,source!);
 if(kind==="qa-after-sink"){
  const record=await enqueueQaDelivery(tenant!,source!);
  const claim=await claimQaDelivery(tenant!,record.id,1);
  if(!("token" in claim)||typeof claim.token!=="string")throw Error("QA_CLAIM_NOT_GRANTED");
  const sent=await consumeQaSink(tenant!,record.id,claim.token);
  await phase13TestFaultBarrier("phase13-qa:after-sink-before-ack");
  const ack=await ackQaDelivery(tenant!,record.id,claim.token);
  return {record,claim,sent,ack};
 }
 throw Error("UNSUPPORTED_CHILD_CASE");
}
try{
 const result=await run();
 process.send?.({phase13Result:result});
}catch(e){process.send?.({phase13Error:String(e)});process.exitCode=1;}
finally{await closeDatabase();}
