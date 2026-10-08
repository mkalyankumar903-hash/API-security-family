import {test} from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {migrate,withTenant,pool,workerPool} from "../packages/database/src/index.js";
import {makeApp} from "../packages/service/src/app.js";
import {drainQueue} from "../packages/worker/src/index.js";
const A="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",B="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const h=(t="local-test-token-alpha")=>({authorization:"Bearer "+t});
const spec=readFileSync(new URL("../fixtures/insecure.openapi.json",import.meta.url),"utf8");
test("Phase 1 real Fastify + PostgreSQL target lifecycle, ownership proof, revisions and Phase 0 regression",async()=>{
 await migrate();
 const app=await makeApp();
 const send=(method:"GET"|"POST"|"PATCH"|"DELETE",url:string,payload?:unknown,token?:string,extra?:Record<string,string>)=>app.inject({method,url,headers:{...h(token),...extra},payload:payload as object|undefined});
 try{
 const key="registration-"+crypto.randomUUID();
 const created=await send("POST","/v1/targets",{name:"Payment API",baseUrl:"https://api.fixture.invalid",environment:"SYNTHETIC"},undefined,{"idempotency-key":key});
 assert.equal(created.statusCode,201,created.body);
 const tid=created.json().id as string;
 assert.equal(created.json().ownership_status,"PENDING_HOST_VERIFICATION");
 assert.equal(created.json().lifecycle,"ACTIVE");
 const retry=await send("POST","/v1/targets",{name:"Payment API",baseUrl:"https://api.fixture.invalid",environment:"SYNTHETIC"},undefined,{"idempotency-key":key});
 assert.equal(retry.statusCode,200,retry.body);assert.equal(retry.json().id,tid);
 assert.equal((await send("POST","/v1/targets",{name:"Different",baseUrl:"https://api.fixture.invalid",environment:"SYNTHETIC"},undefined,{"idempotency-key":key})).statusCode,409);
 const raceKey="concurrent-"+crypto.randomUUID();
 const racePayload={name:"Race-safe registration",baseUrl:"https://race.fixture.invalid",environment:"SYNTHETIC"};
 const duplicates=await Promise.all([send("POST","/v1/targets",racePayload,undefined,{"idempotency-key":raceKey}),send("POST","/v1/targets",racePayload,undefined,{"idempotency-key":raceKey})]);
 assert.deepEqual(duplicates.map(x=>x.statusCode).sort((a,b)=>a-b),[200,201]);
 assert.equal(duplicates[0].json().id,duplicates[1].json().id,"Concurrent retries must yield one canonical target");
 const rebooted=await makeApp();
 try{assert.equal((await rebooted.inject({method:"GET",url:"/v1/targets/"+tid,headers:h()})).statusCode,200,"New service instance sees persisted target");}
 finally{await rebooted.close();}
 const filtered=await send("GET","/v1/targets?search=payment&environment=SYNTHETIC&lifecycle=ACTIVE");
 assert.ok(filtered.json().some((r:{id:string})=>r.id===tid));
 assert.equal((await send("GET","/v1/targets/"+tid,undefined,"local-test-token-beta")).statusCode,404);
 // Real API mutation attempts by tenant B must never cross RLS (including archival and verification).
 for(const [route,body] of [
  ["/v1/targets/"+tid,{revision:1,name:"Forged tenant rename"}]
 ] as [string,object][]){
  assert.equal((await send("PATCH",route,body,"local-test-token-beta")).statusCode,404);
 }
 for(const [route,body] of [
  ["/v1/targets/"+tid+"/lifecycle",{revision:1,action:"ARCHIVE"}],
  ["/v1/targets/"+tid+"/lifecycle",{revision:1,action:"REVOKE"}],
  ["/v1/targets/"+tid+"/verification/challenges",{revision:1}],
  ["/v1/targets/"+tid+"/scopes",{revision:1,proposal:{origins:["https://api.fixture.invalid"],paths:["/"],exclusions:[],methods:["GET"],operations:[],maxRequests:0,windowStart:null,windowEnd:null}}],
  ["/v1/targets/"+tid+"/credentials",{revision:1,reference:"credref:otherfixture01"}]
 ] as [string,object][])assert.equal((await send("POST",route,body,"local-test-token-beta")).statusCode,404,route);
 for(const path of ["","/scopes","/credentials","/verification/challenges","/verification/decisions","/history"]){
  assert.equal((await send("GET","/v1/targets/"+tid+path,undefined,"local-test-token-beta")).statusCode,404,path);
 }
 let current=created.json() as {id:string;revision:number;verification_version:number;ownership_status:string;scope_revision:number};
 const firstChallenge=await send("POST","/v1/targets/"+tid+"/verification/challenges",{revision:current.revision});
 assert.equal(firstChallenge.statusCode,200,firstChallenge.body);
 const oldChallenge=firstChallenge.json().id as string;
 const scopeBody={origins:["https://api.fixture.invalid"],paths:["/","/v1/*"],exclusions:["/admin"],methods:["GET","HEAD"],operations:[],maxRequests:0,windowStart:null,windowEnd:null};
 const invalidScope=await send("POST","/v1/targets/"+tid+"/scopes",{revision:current.revision,proposal:{...scopeBody,origins:["https://other.invalid"]}});
 assert.equal(invalidScope.statusCode,400);
 const scope=await send("POST","/v1/targets/"+tid+"/scopes",{revision:current.revision,proposal:scopeBody});
 assert.equal(scope.statusCode,200,scope.body);
 assert.equal(scope.json().scopeRevision,1);assert.equal(scope.json().authority,"CUSTOMER_PROPOSED");
 assert.equal((await send("POST","/v1/test-authority/attest",{targetId:tid,challengeId:oldChallenge})).statusCode,409);
 const currentResult=await send("GET","/v1/targets/"+tid);current=currentResult.json();
 assert.equal(current.ownership_status,"PENDING_HOST_VERIFICATION");assert.equal(current.verification_version,2);
 assert.equal((await send("POST","/v1/targets/"+tid+"/scopes",{revision:1,proposal:scopeBody})).statusCode,409);
 const ch=await send("POST","/v1/targets/"+tid+"/verification/challenges",{revision:current.revision});
 assert.equal(ch.statusCode,200,ch.body);const cid=ch.json().id as string;
 assert.equal((await send("POST","/v1/test-authority/attest",{targetId:tid,challengeId:cid}, "local-test-token-beta")).statusCode,404);
 const signed=await send("POST","/v1/test-authority/attest",{targetId:tid,challengeId:cid});
 assert.equal(signed.statusCode,200,signed.body);
 const proof=signed.json().attestation as string;
 const forged=await send("POST","/v1/targets/"+tid+"/verification/evidence",
   {challengeId:cid,evidenceType:"SIGNED_SYNTHETIC_ATTESTATION",attestation:proof.slice(0,-2)+"aa"});
 assert.equal(forged.statusCode,403,forged.body);
 const claimed=await send("POST","/v1/targets/"+tid+"/verification/evidence",
  {challengeId:cid,evidenceType:"CUSTOMER_CLAIM",attestation:"I uploaded a screenshot and own this DNS"});
 assert.equal(claimed.statusCode,202,claimed.body);assert.equal(claimed.json().verified,false);
 assert.equal((await send("GET","/v1/targets/"+tid)).json().ownership_status,"PENDING_HOST_VERIFICATION");
 assert.equal((await send("POST","/v1/targets/"+tid+"/verification/evidence",{challengeId:cid,evidenceType:"HOST_ATTESTATION",attestation:"claimed"})).statusCode,503);
 const verified=await send("POST","/v1/targets/"+tid+"/verification/evidence",
  {challengeId:cid,evidenceType:"SIGNED_SYNTHETIC_ATTESTATION",attestation:proof});
 assert.equal(verified.statusCode,200,verified.body);
 assert.equal(verified.json().status,"SYNTHETIC_VERIFIED_TEST_ONLY");assert.equal(verified.json().hostVerified,false);assert.equal(verified.json().liveExecutionAuthorized,false);
 assert.equal((await send("POST","/v1/targets/"+tid+"/verification/evidence",{challengeId:cid,evidenceType:"SIGNED_SYNTHETIC_ATTESTATION",attestation:proof})).statusCode,409);
 assert.equal((await send("GET","/v1/targets/"+tid+"/verification/decisions")).json().length,1);
 assert.equal((await send("GET","/v1/targets/"+tid)).json().ownership_status,"SYNTHETIC_VERIFIED_TEST_ONLY");
 const badRef=await send("POST","/v1/targets/"+tid+"/credentials",{revision:current.revision,reference:"Bearer very-secret"});
 assert.equal(badRef.statusCode,400,badRef.body);
 const goodRef=await send("POST","/v1/targets/"+tid+"/credentials",{revision:current.revision,reference:"credref:syntheticfixture0001"});
 assert.equal(goodRef.statusCode,201,goodRef.body);
 assert.equal(goodRef.json().hostAuthorized,false);
 assert.equal((await send("GET","/v1/targets/"+tid+"/credentials")).json().length,1);
 assert.equal((await send("GET","/v1/targets/"+tid+"/credentials",undefined,"local-test-token-beta")).statusCode,404);
 const upload=await send("POST","/v1/targets/"+tid+"/specifications",{filename:"fixture.json",content:spec});
 assert.equal(upload.statusCode,201,upload.body);
 const assess=await send("POST","/v1/targets/"+tid+"/assessments",{specificationId:upload.json().id,mode:"SPEC_ONLY"},undefined,{"idempotency-key":"assessment-"+crypto.randomUUID()});
 assert.equal(assess.statusCode,201,assess.body);
 assert.equal(await drainQueue(),1);
 assert.equal((await send("GET","/v1/assessments/"+assess.json().id+"/report")).statusCode,200);
 const last=await send("GET","/v1/targets/"+tid);const rev=last.json().revision as number;
 const parallel=await Promise.all([
  send("PATCH","/v1/targets/"+tid,{revision:rev,name:"Payments API Updated"}),
  send("PATCH","/v1/targets/"+tid,{revision:rev,name:"Payments API Conflicting"})
 ]);
 assert.deepEqual(parallel.map(p=>p.statusCode).sort((a,b)=>a-b),[200,409]);
 const latest=(await send("GET","/v1/targets/"+tid)).json();
 assert.equal(latest.revision,rev+1);
 const changed=await send("PATCH","/v1/targets/"+tid,{revision:latest.revision,baseUrl:"https://new.fixture.invalid"});
 assert.equal(changed.statusCode,200,changed.body);
 assert.equal(changed.json().ownership_status,"PENDING_HOST_VERIFICATION");assert.equal(changed.json().scope_revision,2);
 assert.equal((await send("GET","/v1/targets/"+tid+"/scopes")).json().length,1); // historic proposal retained
 const suspend=await send("POST","/v1/targets/"+tid+"/lifecycle",{revision:changed.json().revision,action:"SUSPEND"});
 assert.equal(suspend.statusCode,200);
 assert.equal((await send("POST","/v1/targets/"+tid+"/assessments",{specificationId:upload.json().id,mode:"SPEC_ONLY"},undefined,{"idempotency-key":"suspended-"+crypto.randomUUID()})).statusCode,409);
 assert.equal((await send("POST","/v1/targets/"+tid+"/specifications",{filename:"fixture.json",content:spec})).statusCode,409);
 assert.equal((await send("POST","/v1/targets/"+tid+"/verification/challenges",{revision:suspend.json().revision})).statusCode,409);
 const restored=await send("POST","/v1/targets/"+tid+"/lifecycle",{revision:suspend.json().revision,action:"RESTORE"});
 assert.equal(restored.statusCode,200);
 const revoked=await send("POST","/v1/targets/"+tid+"/lifecycle",{revision:restored.json().revision,action:"REVOKE"});
 assert.equal(revoked.statusCode,200);
 assert.equal((await send("POST","/v1/targets/"+tid+"/assessments",{specificationId:upload.json().id,mode:"SPEC_ONLY"},undefined,{"idempotency-key":"revoked-"+crypto.randomUUID()})).statusCode,409);
 assert.equal((await send("POST","/v1/targets/"+tid+"/lifecycle",{revision:revoked.json().revision,action:"RESTORE"})).statusCode,409);
 assert.equal((await send("GET","/v1/targets/"+tid+"/history")).json().length>=8,true);
 assert.equal((await send("GET","/v1/targets/"+tid+"/history",undefined,"local-test-token-beta")).statusCode,404);
 await assert.rejects(()=>withTenant(A,async tx=>tx.query("DELETE FROM api_target_events WHERE target_id=$1",[tid])),/PHASE1_IMMUTABLE_HISTORY/);
 await assert.rejects(()=>withTenant(A,async tx=>tx.query("UPDATE api_target_scopes SET proposal='{}'::jsonb WHERE target_id=$1",[tid])),/PHASE1_IMMUTABLE_HISTORY/);
 const historyCount=await withTenant(A,async tx=>(await tx.query("SELECT count(*)::integer AS n FROM api_target_events WHERE target_id=$1",[tid])).rows[0].n as number);
 assert.ok(historyCount>=8);
 const foreign=await withTenant(B,async tx=>(await tx.query("SELECT count(*)::integer AS n FROM api_target_events WHERE target_id=$1",[tid])).rows[0].n as number);
 assert.equal(foreign,0);
 assert.equal((await pool.query("SELECT * FROM api_target_challenges LIMIT 1")).rowCount,0,"Unscoped app connection must see no challenge rows through FORCE RLS");
 const another=await send("POST","/v1/targets",{name:"Archivable",baseUrl:"https://archived.fixture.invalid",environment:"PRODUCTION"});
 assert.equal(another.statusCode,201);
 const archived=await send("POST","/v1/targets/"+another.json().id+"/lifecycle",{revision:another.json().revision,action:"ARCHIVE"});
 assert.equal(archived.statusCode,200);assert.equal(archived.json().lifecycle,"ARCHIVED");
 assert.equal((await send("GET","/v1/targets/"+another.json().id)).json().lifecycle,"ARCHIVED");
 }finally{await app.close();await pool.end();await workerPool.end();}
});
