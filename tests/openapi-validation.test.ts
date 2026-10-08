import {test} from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {parseAndValidateSpec} from "../packages/assessment-engine/src/index.js";
const read=(f:string)=>readFileSync(new URL("../fixtures/"+f,import.meta.url),"utf8");
test("official offline OAS3.1 and Swagger 2.0 structure passes",async()=>{
  assert.equal((await parseAndValidateSpec(read("insecure.openapi.json"))).operations.length,3);
  assert.equal((await parseAndValidateSpec(read("secure.openapi.json"))).operations.length,2);
  assert.equal((await parseAndValidateSpec(read("valid-swagger.yaml"))).format,"SWAGGER_2");
});
test("rejects missing mandatory info/responses/security schema",async()=>{
  for(const name of ["invalid-no-info.json","invalid-no-responses.json","invalid-security.json","invalid-broken-ref.yaml"]) {
    await assert.rejects(()=>parseAndValidateSpec(read(name)),/INVALID|BROKEN|SCHEMA/);
  }
});
test("offline spec validation never permits external refs, yaml aliases or oversized payloads",async()=>{
  for(const name of ["invalid-remote-ref.json","invalid-alias.yaml"]){
    await assert.rejects(()=>parseAndValidateSpec(read(name)));
  }
  await assert.rejects(()=>parseAndValidateSpec("x".repeat(1048577)));
});
test("unsupported callback runtime analysis is explicitly flagged",async()=>{
  const obj=JSON.parse(read("secure.openapi.json"));
  obj.paths["/accounts"].get.callbacks={onUpdate:{"{$request.body#/callbackUrl}":{post:{responses:{"200":{description:"callback"}}}}}};
  const normalized=await parseAndValidateSpec(JSON.stringify(obj));
  assert.ok(normalized.warnings.some(w=>w.includes("callbacks")));
});
