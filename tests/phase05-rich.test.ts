import {test} from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {importOfflineDocument} from "../packages/discovery/src/index.js";
import {buildRichInventory} from "../packages/discovery/src/rich.js";
import {detectRichInventory} from "../packages/assessment-engine/src/rich.js";
const sample=readFileSync(new URL("../fixtures/phase2-openapi30-v2.json",import.meta.url),"utf8");
test("phase05-v2 genuinely detects previously unsupported declaration gaps using immutable rich metadata",async()=>{
 const source=JSON.parse(sample);
 const op=source.paths["/bills"].post;
 op.parameters=[{name:"tag",in:"query",schema:{type:"string"}},
  {name:"labels",in:"query",schema:{type:"array",items:{type:"string"}}}];
 op.requestBody.content["application/json"].schema={type:"object",additionalProperties:true,properties:{label:{type:"string"}}};
 const raw=JSON.stringify(source);
 const v1=await importOfflineDocument(raw),rich=buildRichInventory(raw,v1);
 assert.ok(rich);
 const out=detectRichInventory(v1,rich!);
 assert.equal(out.engineVersion,"inventory-v2");
 assert.equal(out.coverage.length,28);
 assert.equal(out.coverage.find(x=>x.ruleId==="API03_STRING_NO_BOUNDS")?.status,"EVALUATED");
 assert.equal(out.coverage.find(x=>x.ruleId==="API03_ADDITIONAL_PROPERTIES")?.status,"EVALUATED");
 const ids=new Set(out.observations.map(x=>x.ruleId));
 for(const id of ["AUTH_OVERRIDE_WEAKENS","STRING_NO_BOUNDS","ARRAY_NO_BOUNDS","ADDITIONAL_PROPERTIES","ERROR_RESPONSE_GAPS"])
  assert.ok(ids.has("API03_"+id),"expected real "+id);
 assert.ok(out.observations.every(x=>x.validationLevel==="SPEC_OBSERVATION"&&x.reviewRequired));
 assert.equal(JSON.stringify(rich).includes("Bill Demo secret"),false);
});
test("phase05-v2 negative declarations and reference ambiguity never manufacture evidence",async()=>{
 const source=JSON.parse(sample);
 const op=source.paths["/bills"].post;
 source.paths["/bills"].get.security=source.security;
 op.responses["400"]={description:"Invalid"};
 op.parameters=[{name:"tag",in:"query",schema:{type:"string",minLength:1,maxLength:12}},
  {name:"labels",in:"query",schema:{type:"array",minItems:1,maxItems:4,items:{type:"string"}}}];
 op.requestBody.content["application/json"].schema={type:"object",additionalProperties:false};
 const raw=JSON.stringify(source),inv=await importOfflineDocument(raw),rich=buildRichInventory(raw,inv);
 assert.ok(rich);
 const result=detectRichInventory(inv,rich!);
 for(const id of ["STRING_NO_BOUNDS","ARRAY_NO_BOUNDS","ADDITIONAL_PROPERTIES"])
  assert.equal(result.observations.some(x=>x.ruleId==="API03_"+id),false);
 const tampered={...rich!,phase02Fingerprint:"0".repeat(64)};
 assert.throws(()=>detectRichInventory(inv,tampered),/INTEGRITY/);
});
test("phase05-v2 does not fabricate Postman formal OpenAPI semantics",async()=>{
 const raw=readFileSync(new URL("../fixtures/phase2-postman21.json",import.meta.url),"utf8");
 const v1=await importOfflineDocument(raw);
 assert.equal(buildRichInventory(raw,v1),null);
});
