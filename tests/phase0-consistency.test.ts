import {test} from "node:test";
import assert from "node:assert/strict";
import Ajv from "ajv";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import {readFileSync} from "node:fs";
import {planSchema,validatePlan,validatePermit,nextOrdinal,MAX_ORDINAL,MAX_WIRE_REQUESTS,type SpecOnlyPlan} from "../packages/contracts/src/policy.js";
import {verifyWirePlanPermit,type WirePlan,type WirePermitRequest} from "../packages/contracts/src/wire-v032.js";
const ajv=new Ajv({strict:false,allErrors:true});
const internal=ajv.compile(planSchema);
const root="../packages/contracts/upstream-v032/schemas/";
const wireAjv=new Ajv2020({strict:false,allErrors:true,unicodeRegExp:false});
addFormats(wireAjv);
for(const name of ["approved-operation","host-delegated-invocation","job-plan","permit-binding-fields","permit-decision","permit-request","trusted-lease-proof"]) {
  wireAjv.addSchema(JSON.parse(readFileSync(new URL(root+name+".schema.json",import.meta.url),"utf8")));
}
const derived=(name:string)=>wireAjv.getSchema("https://contracts.lumicsec.local/api-family/phase0-v032/"+name+".schema.json")!;
const fixture=JSON.parse(readFileSync(new URL("../packages/contracts/upstream-v032/fixtures/readonly-plan-golden.json",import.meta.url),"utf8"));
const safePlan=(method:string,mode="READ_ONLY_PROBE")=>({...fixture,execution_mode:mode,allowed_methods:[method]});

test("C1 provisional internal schema accepts GET/HEAD but never OPTIONS or any write",()=>{
  for(const mode of ["READ_ONLY_PROBE","CONTROLLED_ACTIVE"] as const) {
    for(const method of ["GET","HEAD"]) {
      assert.equal(internal({mode,methods:[method],maxRequests:1}),true,JSON.stringify(internal.errors));
      assert.throws(()=>validatePlan({mode,methods:[method],maxRequests:1}),/LIVE_PROBE_NOT_ENABLED/);
    }
    for(const method of ["OPTIONS","POST","PUT","PATCH","DELETE","TRACE"]){
      assert.equal(internal({mode,methods:[method],maxRequests:1}),false,method+" was admitted");
      assert.throws(()=>validatePlan({mode,methods:[method],maxRequests:1}),/INVALID_PLAN/);
    }
  }
});
test("C1 candidate-derived wire job-plan accepts GET+HEAD individually and together",()=>{
  for(const method of ["GET","HEAD"]){
    assert.equal(derived("job-plan")(safePlan(method)),true,method+" "+JSON.stringify(derived("job-plan").errors));
  }
  assert.equal(derived("job-plan")({...fixture,allowed_methods:["GET","HEAD"]}),true);
});
test("C1 wire job-plan rejects OPTIONS and mutations for BOTH provisional read-only modes",()=>{
  for(const mode of ["READ_ONLY_PROBE","CONTROLLED_ACTIVE"]){
    for(const method of ["OPTIONS","POST","PUT","PATCH","DELETE","TRACE"]){
      assert.equal(derived("job-plan")(safePlan(method,mode)),false,mode+" "+method);
    }
    for(const method of ["GET","HEAD"])assert.equal(derived("job-plan")(safePlan(method,mode)),true,mode+" "+method);
  }
});
test("C1 permit-request derived schema narrows the method field to GET/HEAD for read-only modes",()=>{
  const doc=JSON.parse(readFileSync(new URL(root+"permit-request.schema.json",import.meta.url),"utf8"));
  for(const mode of ["READ_ONLY_PROBE","CONTROLLED_ACTIVE"]) {
    const clause=doc.allOf.find((c:{if?:{properties?:{execution_mode?:{const?:string}}}})=>c.if?.properties?.execution_mode?.const===mode);
    assert.deepEqual(clause.then.properties.method.enum,["GET","HEAD"]);
  }
});
test("C2 SPEC_ONLY requires exact zero network budget/methods in internal policy",()=>{
  const valid:SpecOnlyPlan={mode:"SPEC_ONLY",methods:[],maxRequests:0};
  assert.equal(internal(valid),true);
  assert.doesNotThrow(()=>validatePlan(valid));
  for(const candidate of [
    {...valid,maxRequests:1},{...valid,maxRequests:-1},{...valid,maxRequests:100000},
    {...valid,methods:["GET"]},{...valid,methods:["HEAD"]},{...valid,methods:["OPTIONS"]},
    {...valid,approvedOperations:["POST /fixture"]}
  ]) {
    assert.equal(internal(candidate),false,JSON.stringify(candidate));
    assert.throws(()=>validatePlan(candidate),/INVALID_PLAN/);
  }
  for(const method of ["GET","HEAD"])assert.throws(()=>validatePlan({mode:"READ_ONLY_PROBE",maxRequests:1,methods:[method]}),/LIVE_PROBE_NOT_ENABLED/);
});
test("C2 wire SPEC_ONLY plan accepts zero budgets and disallows any network authority",()=>{
  const offline={
    ...fixture,execution_mode:"SPEC_ONLY",
    max_requests:0,max_concurrency:0,allowed_methods:[],allowed_origins:[],allowed_paths:[],
    max_request_bytes:0,max_response_bytes:0,max_redirects:0,connect_timeout_ms:0,
    per_request_timeout_ms:0,max_total_request_bytes:0,max_total_response_bytes:0,approved_operations:[],
    mutation_approval_reference:null,fixture_set_reference:null
  };
  assert.equal(derived("job-plan")(offline),true,JSON.stringify(derived("job-plan").errors));
  for(const changed of [{...offline,max_requests:1},{...offline,allowed_methods:["GET"]},{...offline,max_concurrency:1}]) {
    assert.equal(derived("job-plan")(changed),false);
  }
  const plan:WirePlan={execution_mode:"SPEC_ONLY",environment_class:"development",max_requests:0,
    allowed_methods:[],allowed_origins:[],allowed_paths:[],approved_operations:[],plan_digest:"sha256:a",
    scope_hash:"sha256:b",credential_profile_reference:null,mutation_approval_reference:null,fixture_set_reference:null,
    cleanup_verification_required:false};
  const permit:WirePermitRequest={execution_mode:"SPEC_ONLY",method:"GET",request_ordinal:1,
    plan_digest:plan.plan_digest,scope_hash:plan.scope_hash,canonical_request_url:"https://api.fixture.invalid/health",
    normalized_path:"/health",credential_profile_reference:null,mutation_approval_reference:null,request_body_digest:null};
  assert.throws(()=>verifyWirePlanPermit(plan,permit),/NO_PERMITS/);
  assert.throws(()=>verifyWirePlanPermit(plan,{...permit,request_ordinal:0}),/NO_PERMITS/);
  assert.throws(()=>validatePermit({allowed:false,reason_code:"DENIED_BUDGET"},
    {budget:0,ordinal:1,requestDigest:"a".repeat(64),now:new Date("2026-10-09T00:00:00Z")}),/INVALID_BUDGET/);
  assert.throws(()=>nextOrdinal(0,0),/BUDGET_EXHAUSTED/);
});
test("wire ceiling 100000 is inclusive, generic safe integer is independent",()=>{
  assert.equal(MAX_WIRE_REQUESTS,100000);
  assert.equal(MAX_ORDINAL,Number.MAX_SAFE_INTEGER);
  assert.equal(nextOrdinal(MAX_ORDINAL-1,MAX_ORDINAL),MAX_ORDINAL);
  const digest="a".repeat(64);
  const ctx={budget:100000,ordinal:100000,requestDigest:digest,now:new Date("2026-10-09T00:00:00Z")};
  const permitted={allowed:true,reason_code:"ALLOWED",permitId:"permit-test",requestOrdinal:100000,
   remainingRequests:0,expiresAt:"2026-10-10T00:00:00Z",requestDigest:digest};
  assert.doesNotThrow(()=>validatePermit(permitted,ctx));
  assert.throws(()=>validatePermit(permitted,{...ctx,budget:100001}),/INVALID_BUDGET/);
  assert.throws(()=>validatePermit({...permitted,requestOrdinal:100001},{...ctx,budget:100001,ordinal:100001}));
  assert.equal(internal({mode:"READ_ONLY_PROBE",methods:["GET"],maxRequests:100000}),true);
  assert.equal(internal({mode:"READ_ONLY_PROBE",methods:["GET"],maxRequests:100001}),false);
});
