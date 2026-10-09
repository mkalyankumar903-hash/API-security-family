import {test} from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {detectInventory,RULE_CATALOG,compareDetection,canonical} from "../packages/assessment-engine/src/inventory.js";
import {importOfflineDocument,type Inventory} from "../packages/discovery/src/index.js";
const fixture=(name:string)=>readFileSync(new URL("../fixtures/"+name,import.meta.url),"utf8");
const pointer="/paths/~1widgets/get";
function baseline():Inventory{return {
 format:"OPENAPI_3_1",normalizationVersion:"phase02-v1",rawFingerprint:"a".repeat(64),normalizedFingerprint:"b".repeat(64),
 metadata:{title:"fixture",declaredVersion:"1.0",servers:["https://api.fixture.invalid"],warnings:[],coverage:"SUPPORTED_PROFILE"},
 schemes:{Bearer:{type:"http",scheme:"bearer"}},assessmentSource:null,
 operations:[{key:"GET /widgets",method:"GET",path:"/widgets",originalPath:"/widgets",operationId:"listWidgets",summary:null,description:null,
 tags:[],folder:[],deprecated:false,pointer,servers:[],auth:{state:"INHERITED",source:pointer+"/security",requirements:[{Bearer:[]}]},
 parameters:[],requestBodies:[],responses:[],warnings:[],unresolved:[]}]
};}
const cloned=(x:Inventory)=>structuredClone(x);
type Change=(x:Inventory)=>void;
const cases:[string,Change][]=[
 ["API03_AUTH_UNDECLARED",x=>{x.operations[0]!.auth={state:"UNDECLARED",source:pointer+"/security",requirements:[]};}],
 ["API03_AUTH_EXPLICIT_NONE",x=>{x.operations[0]!.auth={state:"EXPLICIT_NONE",source:pointer+"/security",requirements:[]};}],
 ["API03_AUTH_SENSITIVE_ROUTE",x=>{x.operations[0]!.path="/admin/accounts";x.operations[0]!.auth.state="UNDECLARED";}],
 ["API03_AUTH_WRITE_PUBLIC",x=>{x.operations[0]!.method="POST";x.operations[0]!.auth.state="EXPLICIT_NONE";}],
 ["API03_AUTH_APIKEY_QUERY",x=>{x.schemes.Bearer={type:"apiKey",in:"query",name:"api_key"};}],
 ["API03_AUTH_BASIC",x=>{x.schemes.Bearer={type:"http-basic",scheme:"basic"};}],
 ["API03_BODY_SCHEMA_MISSING",x=>{x.operations[0]!.requestBodies.push({mediaType:"application/json",status:null,schemaFingerprint:null,
 type:null,requiredProperties:[],nullable:false,composition:[],pointer:pointer+"/requestBody/content/application~1json/schema",description:null});}],
 ["API03_NUMBER_NO_RANGE",x=>{x.operations[0]!.parameters.push({name:"count",in:"query",required:false,type:"integer",format:null,
 schemaFingerprint:"a".repeat(64),pointer:pointer+"/parameters/0",constraints:{}});}],
 ["API03_PATH_PARAMETER_WEAK",x=>{x.operations[0]!.parameters.push({name:"id",in:"path",required:true,type:null,format:null,
 schemaFingerprint:null,pointer:pointer+"/parameters/0",constraints:{}});}],
 ["API03_REQUEST_SENSITIVE_FIELD",x=>{x.operations[0]!.requestBodies.push({mediaType:"application/json",status:null,schemaFingerprint:"f".repeat(64),
 type:"object",requiredProperties:["password"],nullable:false,composition:[],pointer:pointer+"/requestBody",description:null});}],
 ["API03_RESPONSE_SENSITIVE_FIELD",x=>{x.operations[0]!.responses.push({mediaType:"application/json",status:"200",schemaFingerprint:"f".repeat(64),
 type:"object",requiredProperties:["access_token"],nullable:false,composition:[],pointer:pointer+"/responses/200",description:null});}],
 ["API03_HTTP_SERVER",x=>{x.metadata.servers=["http://api.fixture.invalid"];}],
 ["API03_UNRESOLVED_SERVER",x=>{x.metadata.warnings=["UNRESOLVED_SERVER_TEMPLATE"];}],
 ["API03_DEPRECATED_OPERATION",x=>{x.operations[0]!.deprecated=true;}],
 ["API03_DEPRECATED_AUTH_SCHEME",x=>{x.schemes.Bearer={type:"http-basic",scheme:"basic"};}]
];
test("each implemented rule has positive and negative fixtures with reproducible pointer/evidence/classification",()=>{
 const base=detectInventory(baseline());
 for(const [id,change] of cases){
  assert.equal(base.observations.filter(x=>x.ruleId===id).length,0,"negative: "+id);
  const positive=cloned(baseline());change(positive);
  const output=detectInventory(positive),observed=output.observations.filter(x=>x.ruleId===id);
  assert.ok(observed.length>0,"positive: "+id);
  for(const obs of observed){
   assert.match(obs.pointer,/^\//);assert.match(obs.fingerprint,/^[a-f0-9]{64}$/);
   assert.match(obs.correlationKey,/^[a-f0-9]{64}$/);
   assert.equal(obs.validationLevel,"SPEC_OBSERVATION");assert.equal(obs.reviewRequired,true);
   assert.ok(["INFORMATIONAL","LOW","MEDIUM","HIGH"].includes(obs.impact));
   assert.ok(["HIGH","MEDIUM","LOW"].includes(obs.confidence));assert.deepEqual(obs.evidence.pointer,obs.pointer);
   assert.ok(obs.remediation);assert.ok(obs.explanation);assert.ok(obs.potentialImpact);
  }
  assert.deepEqual(detectInventory(positive),output,"deterministic: "+id);
  assert.equal(output.coverage.find(x=>x.ruleId===id)?.matches,observed.length);
 }
});
test("catalog records all 28 requested rules, unresolved are SKIPPED not fabricated positive detections",()=>{
 assert.equal(RULE_CATALOG.length,28);
 assert.equal(new Set(RULE_CATALOG.map(x=>x.id)).size,28);
 const output=detectInventory(baseline());
 assert.equal(output.coverage.length,28);
 assert.equal(output.coverage.filter(x=>x.status==="SKIPPED").length,RULE_CATALOG.filter(x=>!!x.unsupported).length);
 assert.equal(output.observations.length,0);
 assert.ok(output.coverage.some(x=>x.ruleId==="API03_EXAMPLE_CREDENTIAL"&&x.reason));
 assert.equal(output.limitations.includes("UNKNOWN != SAFE"),true);
});
test("four imported format inventories support only appropriate rule semantics, without Postman scripts or secrets",async()=>{
 for(const name of ["phase2-openapi30-v1.json","phase2-openapi31.yaml","valid-swagger.yaml","phase2-postman21.json"]){
  const inv=await importOfflineDocument(fixture(name)),result=detectInventory(inv);
  assert.equal(result.engineVersion,"inventory-v1");
  assert.equal(result.coverage.length,28);
  assert.deepEqual(detectInventory(inv),result);
  assert.ok(result.observations.every(x=>x.evidence.pointer.startsWith("/")));
  if(inv.format==="POSTMAN_2_1"){
   assert.equal(result.coverage.find(x=>x.ruleId==="API03_NUMBER_NO_RANGE")?.status,"SKIPPED");
   assert.ok(!JSON.stringify(result).includes("test-secret-DO-NOT-PERSIST"));
   assert.ok(result.warnings.includes("POSTMAN_SCRIPT_IGNORED"));
  }
 }
});
test("cross-version correlation differentiates newly, no longer, unchanged and changed evidence",()=>{
 const a=baseline(),b=cloned(a);a.operations[0]!.auth.state="UNDECLARED";b.operations[0]!.auth.state="EXPLICIT_NONE";
 const from=detectInventory(a),to=detectInventory(b),difference=compareDetection(from,to);
 assert.equal(difference.comparable,true);
 assert.ok(difference.newlyObserved.some(x=>x.ruleId==="API03_AUTH_EXPLICIT_NONE"));
 assert.ok(difference.noLongerObserved.some(x=>x.ruleId==="API03_AUTH_UNDECLARED"));
 const changed=cloned(a);changed.operations[0]!.auth.state="EXPLICIT_NONE";changed.operations[0]!.path="/admin/accounts";
 const diff2=compareDetection(from,detectInventory(changed));
 assert.equal(diff2.comparable,true);
 assert.ok(compareDetection(to,to).stillObserved.length===to.observations.length);
 const incompatible=structuredClone(to);incompatible.coverage[0]!.revision="9.0.0";
 assert.equal(compareDetection(from,incompatible).comparable,false);
});
test("malformed/untrusted snapshots fail closed, canonical serialization independent of key ordering",()=>{
 const x=baseline();x.normalizationVersion="evil" as "phase02-v1";
 assert.throws(()=>detectInventory(x),/UNSUPPORTED_OR_TAMPERED/);
 const oversize=baseline();oversize.operations=Array.from({length:5001},()=>structuredClone(oversize.operations[0]!));
 assert.throws(()=>detectInventory(oversize),/INVENTORY_BUDGET/);
 assert.equal(canonical({b:2,a:{z:2,y:1}}),canonical({a:{y:1,z:2},b:2}));
});
test("no raw secret values are ever captured in returned detection facts or coverage",()=>{
 const x=baseline();x.operations[0]!.description="actual token VALUE=PRIVATE-DO-NOT-STORE";
 x.operations[0]!.responses.push({mediaType:"application/json",status:"200",schemaFingerprint:"a".repeat(64),type:"object",
 requiredProperties:["password","secret"],nullable:false,composition:[],pointer:pointer+"/responses/200",description:null});
 const result=detectInventory(x);
 assert.ok(result.observations.some(o=>o.ruleId==="API03_RESPONSE_SENSITIVE_FIELD"));
 assert.ok(!JSON.stringify(result).includes("PRIVATE-DO-NOT-STORE"));
 assert.ok(!JSON.stringify(result).includes('"password"'));
});
