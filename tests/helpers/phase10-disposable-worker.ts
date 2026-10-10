/** Actual SIGKILL qualification child. Never uses customer network or a mock lease. */
import {claimJob,renewWorkerClaim} from "../../packages/database/src/index.js";
const claim=await claimJob();
if(!claim||typeof process.send!=="function")process.exit(31);
if(process.argv[2]==="heartbeat"&&!await renewWorkerClaim(claim))process.exit(32);
process.send({claim,stage:process.argv[2]??"claimed"});
// Parent process force-kills this worker. Do not close database connections or
// perform graceful shutdown; this exercises real orphaned-lease recovery.
setInterval(()=>{},10000);
