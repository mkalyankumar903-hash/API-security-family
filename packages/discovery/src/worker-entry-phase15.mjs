import {workerData,parentPort} from "node:worker_threads";
import {syncBuiltinESMExports} from "node:module";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import tls from "node:tls";
import dns from "node:dns";
// Dedicated COMPILED private release path. Accepted source-tree entry uses tsx;
// built package must not require a development-only TypeScript loader.
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
try{
 const {importOfflineDocument}=await import("./index.js");
 const inventory=await importOfflineDocument(String(workerData.content));
 parentPort?.postMessage({ok:true,inventory,blockedAttempts});
}catch(e){
 const code=typeof e?.code==="string"?e.code:"DOCUMENT_VALIDATION_FAILED";
 parentPort?.postMessage({ok:false,code,blockedAttempts});
}
