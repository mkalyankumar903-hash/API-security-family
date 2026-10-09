/** Disposable real Phase09 synthetic orchestrator process: OS SIGKILL evidence only.
 * The parent SIGKILLs at the exact durable boundary reported over IPC.
 * Never injects production credentials or customer-target network requests. */
import {claimJob} from "../../packages/database/src/index.js";
import {processPtOrchestrationJob} from "../../packages/worker/src/pt-orchestrator.js";
const claimed=await claimJob();
if(!claimed||!process.send)process.exit(31);
const scenario=process.argv[2];
let signaled=false;
const pause=async(kind:string,detail:string)=>{
 if(signaled)return;
 signaled=true;
 process.send?.({kind,detail,claim:claimed});
 await new Promise<void>(()=>{});
};
setInterval(()=>{},10000); // Preserve running process until the parent delivers SIGKILL.
await processPtOrchestrationJob(claimed.tenant_id,claimed.assessment_id,claimed.claim_token,{
 afterEvaluation:async n=>{
  if(scenario==="after-evaluation"&&n===1)await pause("after-evaluation",String(n));
 },
 afterCheckpoint:async stage=>{
  if(scenario==="after-checkpoint"&&stage==="authorization")await pause("after-checkpoint",stage);
 }
});
if(scenario==="after-report")await pause("after-report","report-committed");
process.exit(0);
