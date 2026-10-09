import {test} from "node:test";
import assert from "node:assert/strict";
import {comparePersistedFindings} from "../packages/service/src/unified.js";
const f=(fingerprint:string,correlationKey:string,ruleVersion="1.0.0")=>
 ({fingerprint,correlationKey,ruleId:"API03_DEMO",ruleVersion,operationKey:"GET /demo",pointer:"/paths/~1demo/get"});
test("Phase05 evidence-aware comparison distinguishes persisted new, changed and no-longer-observed facts",()=>{
 const out=comparePersistedFindings([f("old","same"),f("gone","removed"),f("persist","persist")],
  [f("new","same"),f("added","new"),f("persist","persist")]);
 assert.equal(out.newlyObserved.length,1);
 assert.equal(out.noLongerObserved.length,1);
 assert.equal(out.stillObserved.length,1);
 assert.equal(out.evidenceChanged.length,1);
 assert.equal(out.evidenceChanged[0].fingerprint,"new");
});
test("Phase05 comparison on empty findings never implies verified security",()=>{
 const out=comparePersistedFindings([],[]);
 assert.deepEqual(out,{newlyObserved:[],noLongerObserved:[],stillObserved:[],evidenceChanged:[]});
});
