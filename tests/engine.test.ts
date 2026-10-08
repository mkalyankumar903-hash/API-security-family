import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { parseSpec, assess } from "../packages/assessment-engine/src/index.js";
const load=(name:string)=>readFileSync(new URL("../fixtures/"+name,import.meta.url),"utf8");
test("real synthetic OpenAPI produces source-derived observations and ordered operation inventory",()=>{
  const spec=parseSpec(load("insecure.openapi.json"));
  assert.equal(spec.operations.length,3);
  assert.deepEqual(spec.operations.map(x=>x.key),["GET /private","GET /public","POST /admin/accounts"]);
  const findings=assess(spec);
  assert.ok(findings.some(x=>x.ruleId==="SPEC_AUTH_UNDECLARED"));
  assert.ok(findings.some(x=>x.ruleId==="SPEC_SENSITIVE_UNDECLARED"));
  assert.ok(findings.some(x=>x.ruleId==="SPEC_HTTP_SERVER"));
  assert.ok(findings.every(x=>x.validationLevel==="SPEC_ONLY"&&x.reviewRequired));
});
test("secure fixture produces zero findings, not hardcoded synthetic results",()=>{
  const spec=parseSpec(load("secure.openapi.json"));
  assert.equal(assess(spec).length,0);
});
test("swagger 2 JSON and YAML are parsed without fetching any URL",()=>{
  const swagger={swagger:"2.0",host:"api.fixture.invalid",schemes:["https"],securityDefinitions:{Token:{type:"apiKey",in:"header",name:"Authorization"}},security:[{Token:[]}],paths:{"/ping":{get:{responses:{200:{description:"ok"}}}}}};
  assert.equal(parseSpec(JSON.stringify(swagger)).operations.length,1);
  assert.equal(parseSpec('swagger: "2.0"\nhost: api.fixture.invalid\npaths:\n  /ping:\n    get:\n      responses:\n        "200":\n          description: ok\n').format,"SWAGGER_2");
});
test("spec input security caps and malicious refs/aliases/versions fail closed",()=>{
  for(const input of [
    '{"openapi":"3.1.0","paths":{"/x":{"get":{"$ref":"https://attacker.invalid/schema"}}}}',
    "openapi: 3.1.0\npaths: &evil {}\nextra: *evil\n",
    "openapi: 3.0.0\npaths: {}\n",
    "x".repeat(1048577)
  ]) assert.throws(()=>parseSpec(input));
});
test("invalid security requirements fail closed",()=>{
  assert.throws(()=>parseSpec(JSON.stringify({openapi:"3.1.0",paths:{"/x":{get:{security:[{"Broken":"not-scopes"}]}}}})));
});
