import {test} from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {parse} from "yaml";
const api=readFileSync(new URL("../docs/phase12-openapi.yaml",import.meta.url),"utf8");
const doc=parse(api) as {openapi:string;security:unknown;paths:Record<string,Record<string,{summary:string;responses:Record<string,unknown>}>>};
const service=readFileSync(new URL("../packages/service/src/phase12.ts",import.meta.url),"utf8")+
 readFileSync(new URL("../packages/service/src/phase12-workflows.ts",import.meta.url),"utf8")+
 readFileSync(new URL("../packages/service/src/phase12-findings.ts",import.meta.url),"utf8");
test("Phase12 OpenAPI 3.1 documents every actual HTTP endpoint and method, no decorative paths",()=>{
 assert.equal(doc.openapi,"3.1.0");
 let count=0;
 for(const [path,methods] of Object.entries(doc.paths)){
  const actual=path.replaceAll("{id}",":id").replaceAll("{key}",":key");
  for(const [method,route] of Object.entries(methods)){
   count++;
   assert(service.includes('app.'+method+'("'+actual+'"'),method.toUpperCase()+" "+path);
   assert(route.summary&&Object.keys(route.responses).length>0);
  }
 }
 assert.equal(count,21);
 const discovered=[...service.matchAll(/app\.(get|post|put|patch|delete)\("(\/v12\/[^"]+)"/g)];
 assert.equal(discovered.length,count,"Every implemented v12 route must be documented");
});
test("Phase12 OpenAPI explicitly calls out only isolated bearer identity, not fake Host identity",()=>{
 assert.match(api,/IsolatedSyntheticTenantBearer/);
 assert.match(api,/not a production Host JWT/);
 assert.match(api,/NEVER|never|NOT/);
 assert.match(api,/customerRuntimeVerified/);
 assert.match(api,/verifiedFixed/);
});
