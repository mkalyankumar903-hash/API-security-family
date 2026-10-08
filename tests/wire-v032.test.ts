import {test} from "node:test";
import assert from "node:assert/strict";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import {readFileSync} from "node:fs";
import {verifyWirePlanPermit, type WirePlan, type WirePermitRequest} from "../packages/contracts/src/wire-v032.js";
const folder="../packages/contracts/upstream-v032/schemas/";
const names=["approved-operation","host-delegated-invocation","job-plan","permit-binding-fields","permit-decision","permit-request","trusted-lease-proof"];
const ajv=new Ajv2020({strict:false,allErrors:true,unicodeRegExp:false});
addFormats(ajv);
for(const name of names) ajv.addSchema(JSON.parse(readFileSync(new URL(folder+name+".schema.json",import.meta.url),"utf8")));
const schema=(name:string)=>ajv.getSchema("https://contracts.lumicsec.local/api-family/phase0-v032/"+name+".schema.json")!;
const original=JSON.parse(readFileSync(new URL("../packages/contracts/upstream-v032/fixtures/readonly-plan-golden.json",import.meta.url),"utf8"));
test("v0.3.2 derived original wire job-plan validates good synthetic candidate",()=>{
  assert.equal(schema("job-plan")(original),true,JSON.stringify(schema("job-plan").errors));
});
test("SCHEMA-01 read-only and controlled-active cannot admit mutation in original wire schema",()=>{
  for(const mode of ["READ_ONLY_PROBE","CONTROLLED_ACTIVE"]){
    const plan={...original,execution_mode:mode,allowed_methods:["GET","POST"]};
    assert.equal(schema("job-plan")(plan),false);
  }
});
test("SCHEMA-03 denial with ALLOWED reason is rejected at schema layer",()=>{
  const denial={allowed:false,reason_code:"ALLOWED",permit_id:null,request_fingerprint:null,
   approved_plan_digest:null,lease_generation:0,policy_revision:"policy-1",authority_revision:"auth-1",
   approved_max_request_bytes:0,approved_max_response_bytes:0,expires_at:null,policy_generation:0,
   permit_binding_digest:null,single_use_egress_token:null,binding_fields:null};
  assert.equal(schema("permit-decision")(denial),false);
});
test("SCHEMA-04 wire ordinal schema max matches original job max_requests=100000",()=>{
  const permit=JSON.parse(readFileSync(new URL(folder+"permit-request.schema.json",import.meta.url),"utf8"));
  const job=JSON.parse(readFileSync(new URL(folder+"job-plan.schema.json",import.meta.url),"utf8"));
  assert.equal(job.properties.max_requests.maximum,100000);
  assert.equal(permit.properties.request_ordinal.maximum,100000);
});
test("wire cross-object budget/method/scope/credential/operation semantics deny mismatches",()=>{
  const plan:WirePlan={execution_mode:"READ_ONLY_PROBE",environment_class:"staging",
    allowed_methods:["GET"],allowed_origins:["https://api.fixture.invalid"],allowed_paths:["/health"],
    approved_operations:[],max_requests:100000,plan_digest:"sha256:a",scope_hash:"sha256:b",
    credential_profile_reference:null,mutation_approval_reference:null,fixture_set_reference:null,cleanup_verification_required:false};
  const req:WirePermitRequest={execution_mode:"READ_ONLY_PROBE",method:"GET",request_ordinal:100000,
    plan_digest:plan.plan_digest,scope_hash:plan.scope_hash,canonical_request_url:"https://api.fixture.invalid/health",
    normalized_path:"/health",credential_profile_reference:null,mutation_approval_reference:null,request_body_digest:null};
  assert.doesNotThrow(()=>verifyWirePlanPermit(plan,req));
  for(const modified of [
    {...req,request_ordinal:100001},{...req,method:"POST"},{...req,plan_digest:"other"},
    {...req,canonical_request_url:"https://another.invalid/health"},
    {...req,normalized_path:"/another"},{...req,credential_profile_reference:"stolen"},
    {...req,mutation_approval_reference:"fake"}
  ]) assert.throws(()=>verifyWirePlanPermit(plan,modified));
  const mutating={...plan,execution_mode:"MUTATING_STAGING",allowed_methods:["POST"],
    mutation_approval_reference:"host-approved",fixture_set_reference:"test-fixture",cleanup_verification_required:true,
    approved_operations:[{method:"POST",origin:"https://api.fixture.invalid",path_template:"/health",body_schema_digest:"sha256:body",credential_profile_reference:null}]};
  const write={...req,method:"POST",execution_mode:"MUTATING_STAGING",mutation_approval_reference:"host-approved",request_body_digest:"sha256:body"};
  assert.doesNotThrow(()=>verifyWirePlanPermit(mutating,write));
  assert.throws(()=>verifyWirePlanPermit({...mutating,environment_class:"production"},write));
  assert.throws(()=>verifyWirePlanPermit(mutating,{...write,request_body_digest:"sha256:wrong"}));
});
