import {test} from "node:test";
import assert from "node:assert/strict";
import {classifyWorkerFailure} from "../packages/worker/src/safety-retry.js";

test("Phase10 transient classification is explicit and bounded",()=>{
 for(const code of ["08000","08003","08006","40001","40P01","57P01","57014"])
  assert.equal(classifyWorkerFailure({code}),"TRANSIENT_PRE_EXECUTION",code);
 for(const input of [null,undefined,"IO error",new Error("timeout"),{code:"23505"},
  {code:"PERMIT_REVOKED"},{code:"PT9_UNCERTAIN_EVALUATION_NO_REPLAY"},{code:"08007"}])
  assert.equal(classifyWorkerFailure(input),"NON_RETRYABLE");
});
