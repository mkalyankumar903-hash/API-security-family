import {workerData,parentPort} from "node:worker_threads";
import {syncBuiltinESMExports} from "node:module";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import tls from "node:tls";
import dns from "node:dns";
import {tsImport} from "tsx/esm/api";
// Worker-local request-denial belt in addition to never dereferencing source/servers.
// This is NOT a substitute for a mandatory production network namespace/egress ACL.
let blockedAttempts=0;
const blocked=()=>{blockedAttempts++;throw new Error("OFFLINE_NETWORK_EGRESS_DENIED");};
http.request=blocked;http.get=blocked;
https.request=blocked;https.get=blocked;
net.connect=blocked;net.createConnection=blocked;
tls.connect=blocked;
dns.lookup=blocked;dns.resolve=blocked;dns.resolve4=blocked;dns.resolve6=blocked;
dns.promises.lookup=async()=>blocked();dns.promises.resolve=async()=>blocked();
globalThis.fetch=async()=>blocked();
syncBuiltinESMExports();
try {
 const {importOfflineDocument}=await tsImport("./index.ts",import.meta.url);
 const inventory=await importOfflineDocument(String(workerData.content));
 parentPort?.postMessage({ok:true,inventory,blockedAttempts});
} catch(e) {
 const code=typeof e?.code==="string"?e.code:"DOCUMENT_VALIDATION_FAILED";
 parentPort?.postMessage({ok:false,code,blockedAttempts});
}
