import {test} from "node:test";
import assert from "node:assert/strict";
import {buildTerminalCoverage} from "../packages/pt/src/terminal-coverage.js";
import {RULES} from "../packages/pt/src/detection.js";
const r=RULES[0]!;
const plan=r.cases.map(c=>({evaluationKey:r.id+":"+c.caseId,ruleId:r.id,caseId:c.caseId}));
test("Phase08 missing evidence and cancellation preserve explicit NOT_RUN and no success",()=>{
 const x=buildTerminalCoverage("test","CANCELLED","CANCELLED_BY_AUTHORITY","SECURE_BASELINE",
  [{id:r.id,revision:r.revision}],plan,[]);
 assert.equal(x.assessmentComplete,false);
 assert.equal(x.verifiedFixed,false);
 assert.equal(x.rules[0]?.status,"NOT_RUN");
 assert.equal(x.totals.notRunEvaluations,r.cases.length);
 assert.match(x.notice,/Assessment incomplete/);
});
test("Phase08 stale reservation never counts as executed and remains inconclusive",()=>{
 const x=buildTerminalCoverage("test","FAILED","PT7_INCOMPLETE_OR_DENIED","SECURE_BASELINE",
  [{id:r.id,revision:r.revision}],plan,[{evaluation_key:plan[0]!.evaluationKey,state:"UNCERTAIN",reason:"LEASE_LOST",evidence:null}]);
 assert.equal(x.rules[0]?.status,"INCONCLUSIVE");
 assert.equal(x.totals.executedEvaluations,0);
 assert.equal(x.totals.uncertainEvaluations,1);
 assert.equal(x.totals.notRunEvaluations,1);
});
test("Phase08 permit denial never becomes PASS",()=>{
 const x=buildTerminalCoverage("test","FAILED","PERMIT_REVOKED","SECURE_BASELINE",
  [{id:r.id,revision:r.revision}],plan,[]);
 assert.equal(x.rules[0]?.status,"BLOCKED");
 assert.equal(x.customerRuntimeVerified,false);
});
