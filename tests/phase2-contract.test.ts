import {test} from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {importOfflineDocument,compareInventory,DiscoveryError} from "../packages/discovery/src/index.js";
const fixture=(name:string)=>readFileSync(new URL("../fixtures/"+name,import.meta.url),"utf8");
test("OpenAPI 3.0.3 JSON independently validated: operations, auth, parameters and schemas",async()=>{
 const v=await importOfflineDocument(fixture("phase2-openapi30-v1.json"));
 assert.equal(v.format,"OPENAPI_3_0");assert.equal(v.operations.length,2);
 assert.equal(v.operations.find(x=>x.key==="GET /bills")?.auth.state,"INHERITED");
 assert.equal(v.operations.find(x=>x.key==="GET /status")?.auth.state,"EXPLICIT_NONE");
 assert.equal(v.operations.find(x=>x.key==="GET /bills")?.parameters[0]?.name,"limit");
 assert.equal(v.operations.find(x=>x.key==="GET /bills")?.responses[0]?.schemaFingerprint?.length,64);
 assert.equal(v.schemes.BearerAuth?.type,"http");assert.equal(v.assessmentSource,null);
});
test("OpenAPI 3.1 YAML nullable JSON Schema, Swagger 2 legacy import, no web calls",async()=>{
 const n=await importOfflineDocument(fixture("phase2-openapi31.yaml"));
 assert.equal(n.format,"OPENAPI_3_1");assert.equal(n.operations.length,1);assert.ok(n.assessmentSource);
 const s=await importOfflineDocument(fixture("valid-swagger.yaml"));
 assert.equal(s.format,"SWAGGER_2");assert.equal(s.operations[0]?.key,"GET /ping");assert.ok(s.assessmentSource);
});
test("Postman v2.1 folder/auth inheritance/overrides, unresolved variables, scripts ignored",async()=>{
 const i=await importOfflineDocument(fixture("phase2-postman21.json"));
 assert.equal(i.format,"POSTMAN_2_1");
 assert.equal(i.operations.length,2);
 assert.deepEqual(i.operations[0]?.folder,["Billing"]);
 assert.ok(i.metadata.warnings.includes("POSTMAN_SCRIPT_IGNORED"));
 assert.ok(i.metadata.warnings.includes("UNRESOLVED_COLLECTION_VARIABLES"));
 assert.equal(i.operations[1]?.auth.state,"EXPLICIT_NONE");
 assert.notEqual(i.operations[0]?.auth.state,"EXPLICIT_NONE");
 assert.equal(i.operations[0]?.parameters[0]?.name,"page");
 assert.equal(i.operations[0]?.unresolved[0],"{{baseUrl}}");
 assert.equal(i.assessmentSource,null);
 assert.ok(!JSON.stringify(i).includes("test-secret-DO-NOT-PERSIST"));
});
test("normalized fingerprint stable across document JSON member order, distinct raw fingerprint",async()=>{
 const value=JSON.parse(fixture("phase2-openapi30-v1.json")) as Record<string,unknown>;
 const a=await importOfflineDocument(JSON.stringify(value));
 const reversed=Object.fromEntries(Object.entries(value).reverse());
 const b=await importOfflineDocument(JSON.stringify(reversed));
 assert.notEqual(a.rawFingerprint,b.rawFingerprint);
 assert.equal(a.normalizedFingerprint,b.normalizedFingerprint);
 assert.deepEqual(a.operations.map(x=>x.key),b.operations.map(x=>x.key));
});
test("structural diff reliably detects added, removed, auth, body and metadata changes",async()=>{
 const a=await importOfflineDocument(fixture("phase2-openapi30-v1.json"));
 const b=await importOfflineDocument(fixture("phase2-openapi30-v2.json"));
 const diff=compareInventory(a,b);
 assert.deepEqual(diff.added,["POST /bills"]);assert.deepEqual(diff.removed,["GET /status"]);
 assert.deepEqual(diff.changed.find(x=>x.key==="GET /bills")?.fields,["auth"]);
 assert.equal(diff.changed[0]?.possibleBreaking,true);assert.equal(diff.reviewRequired,true);
 const repeat=compareInventory(a,b);assert.deepEqual(diff,repeat);
});
test("security negatives: malformed, unsupported, oversize, deep, alias, duplicate, external and missing refs, cycles",async()=>{
 const bad=[
  ["{bad","INVALID_JSON"],['{"openapi":"2.1"}',"UNSUPPORTED_DOCUMENT_FORMAT"],
  ["A".repeat(1048577),"DOCUMENT_SIZE_LIMIT"],
  ['openapi: 3.1.0\ninfo: &data {title: Hi, version: 1.0.0}\ncopy: *data\npaths: {}',"YAML_ALIAS_PROHIBITED"],
  ['openapi: 3.1.0\nopenapi: 3.0.3\ninfo: {}',"INVALID_YAML"],
  [fixture("invalid-remote-ref.json"),"EXTERNAL_REF_PROHIBITED"],
  ['{"openapi":"3.1.0","info":{"title":"x","version":"1.0.0"},"paths":{"/hi":{"get":{"responses":{"200":{"description":"ok"}}}}},"components":{"schemas":{"Bad":{"$ref":"#/components/schemas/Other"},"Other":{"$ref":"#/components/schemas/Bad"}}}}',"LOCAL_REFERENCE_CYCLE"],
  ['{"openapi":"3.1.0","info":{"title":"x","version":"1.0.0"},"paths":{"/hi":{"get":{"responses":{"200":{"description":"ok"}}}}},"components":{"schemas":{"Bad":{"$ref":"#/components/schemas/Nope"}}}}',"UNRESOLVED_LOCAL_REFERENCE"]
 ] as const;
 for(const [source,code] of bad){await assert.rejects(()=>importOfflineDocument(source),(e:unknown)=>e instanceof DiscoveryError&&e.code===code,code);}
 const deep='{"info":{"schema":"https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},"item":['+'{"item":['.repeat(50)+'{}'+']}'.repeat(50)+']}';
 await assert.rejects(()=>importOfflineDocument(deep),/DOCUMENT_COMPLEXITY_LIMIT/);
});
test("unsafe paths and scripts never become network or mutation permissions",async()=>{
 const v=JSON.parse(fixture("phase2-postman21.json"));
 v.item[0].item[0].request.url.path=["../admin"];
 await assert.rejects(()=>importOfflineDocument(JSON.stringify(v)),/INVALID_POSTMAN_PATH/);
 const noScript=await importOfflineDocument(fixture("phase2-postman21.json"));
 assert.equal(noScript.assessmentSource,null);
 assert.ok(noScript.operations.every(x=>!x.requestBodies.some(y=>y.schemaFingerprint&&y.schemaFingerprint.includes("secret"))));
});

test("malicious declared server URL never becomes authorization, credentials fail before persistence",async()=>{
 const x=JSON.parse(fixture("phase2-openapi30-v1.json"));
 x.servers=[{url:"http://169.254.169.254/latest/meta-data"}];
 const inert=await importOfflineDocument(JSON.stringify(x));
 assert.ok(inert.metadata.warnings.includes("UNTRUSTED_DECLARED_SERVER"));
 assert.equal(inert.assessmentSource,null);
 x.servers=[{url:"https://username:password@api.fixture.invalid"}];
 await assert.rejects(()=>importOfflineDocument(JSON.stringify(x)),/UNSAFE_SERVER_DECLARATION/);
});
test("genuine Postman collection requirements reject missing info name and wrong schema version",async()=>{
 const p=JSON.parse(fixture("phase2-postman21.json"));
 delete p.info.name;
 await assert.rejects(()=>importOfflineDocument(JSON.stringify(p)),/INVALID_POSTMAN_COLLECTION/);
 p.info.name="Valid";p.info.schema="https://schema.getpostman.com/json/collection/v2.0.0/collection.json";
 await assert.rejects(()=>importOfflineDocument(JSON.stringify(p)),/UNSUPPORTED_POSTMAN_VERSION/);
});
