import {test} from "node:test";
import assert from "node:assert/strict";
import { validatePlan, validatePermit, nextOrdinal, MAX_ORDINAL } from "../packages/contracts/src/policy.js";
test("SCHEMA-01 READ_ONLY_PROBE denies mutation at JSON Schema and runtime gates",()=>{
  assert.throws(()=>validatePlan({mode:"READ_ONLY_PROBE",methods:["GET","POST"],maxRequests:10}));
  assert.throws(()=>validatePlan({mode:"READ_ONLY_PROBE",methods:["GET"],maxRequests:10}),/LIVE_PROBE_NOT_ENABLED/);
});
test("SCHEMA-02 CONTROLLED_ACTIVE and MUTATING_STAGING never authorize unsafe mutation",()=>{
  assert.throws(()=>validatePlan({mode:"CONTROLLED_ACTIVE",methods:["PATCH"],maxRequests:10}));
  assert.throws(()=>validatePlan({mode:"MUTATING_STAGING",methods:["POST"],maxRequests:10,environment:"PRODUCTION"}));
  assert.throws(()=>validatePlan({mode:"MUTATING_STAGING",methods:["POST"],maxRequests:10,environment:"STAGING",approvedOperations:["POST /test"],fixtureBoundary:"synthetic-only",cleanupVerification:true}),/NOT_ENABLED/);
  assert.doesNotThrow(()=>validatePlan({mode:"SPEC_ONLY",methods:[],maxRequests:1}));
});
const digest="a".repeat(64);
const context={budget:10,ordinal:1,requestDigest:digest,now:new Date("2026-10-09T00:00:00Z")};
const allowed={allowed:true,reason_code:"ALLOWED",permitId:"permit-1",requestOrdinal:1,remainingRequests:9,expiresAt:"2026-10-10T00:00:00Z",requestDigest:digest};
test("SCHEMA-03 reject contradictory decisions, expiry and request binding mismatch",()=>{
  validatePermit(allowed,context);
  for(const p of [{...allowed,allowed:false},{...allowed,reason_code:"DENIED_POLICY"},{...allowed,permitId:undefined},{...allowed,expiresAt:"2026-10-08T00:00:00Z"},{...allowed,requestDigest:"b".repeat(64)},{allowed:false,reason_code:"ALLOWED"}]) assert.throws(()=>validatePermit(p,context));
  assert.doesNotThrow(()=>validatePermit({allowed:false,reason_code:"DENIED_BUDGET"},context));
});
test("SCHEMA-04 enforce inclusive 1..budget ordinals and safe integer bounds",()=>{
  assert.equal(nextOrdinal(0,1),1);
  assert.equal(nextOrdinal(MAX_ORDINAL-1,MAX_ORDINAL),MAX_ORDINAL);
  for(const [used,budget] of ([[1,1],[-1,5],[1.5,5],[0,MAX_ORDINAL+1],[MAX_ORDINAL,MAX_ORDINAL]] as [number,number][]))assert.throws(()=>nextOrdinal(used,budget));
  assert.throws(()=>validatePermit({...allowed,requestOrdinal:11},{...context,ordinal:11}));
  assert.throws(()=>validatePermit({...allowed,remainingRequests:10},context));
});
