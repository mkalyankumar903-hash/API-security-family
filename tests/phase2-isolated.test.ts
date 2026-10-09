import {test} from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {importOfflineIsolated} from "../packages/discovery/src/isolated.js";
import {DiscoveryError} from "../packages/discovery/src/index.js";
const fixture=(name:string)=>readFileSync(new URL("../fixtures/"+name,import.meta.url),"utf8");
test("worker-thread parser isolates valid OpenAPI3.0 and Postman2.1 with bounded output",async()=>{
 const a=await importOfflineIsolated(fixture("phase2-openapi30-v1.json"));
 const b=await importOfflineIsolated(fixture("phase2-postman21.json"));
 assert.equal(a.format,"OPENAPI_3_0");assert.equal(b.format,"POSTMAN_2_1");
 assert.equal(a.operations.length,2);assert.equal(b.operations.length,2);
 assert.equal(a.normalizedFingerprint.length,64);
});
test("isolated parser returns only safe diagnostic categories, no raw source secrets",async()=>{
 const raw="{PRIVATE_TEST_SECRET_dont_log";
 await assert.rejects(()=>importOfflineIsolated(raw),(err:unknown)=>err instanceof DiscoveryError && err.code==="INVALID_JSON" && !err.message.includes("SECRET"));
 await assert.rejects(()=>importOfflineIsolated("Z".repeat(1048577)),/DOCUMENT_SIZE_LIMIT/);
});
test("four-worker bound rejects excess simultaneous imports rather than allocating unbounded memory",async()=>{
 const content=fixture("phase2-openapi30-v1.json");
 const results=await Promise.allSettled(Array.from({length:5},()=>importOfflineIsolated(content)));
 assert.equal(results.filter(x=>x.status==="fulfilled").length,4);
 const rejected=results.find(x=>x.status==="rejected");
 assert.ok(rejected&&rejected.status==="rejected"&&rejected.reason instanceof DiscoveryError&&rejected.reason.code==="IMPORT_CONCURRENCY_LIMIT");
});
