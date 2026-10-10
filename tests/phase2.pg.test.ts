import {test} from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {makeApp} from "../packages/service/src/app.js";
import {migrate,pool,workerPool,withTenant} from "../packages/database/src/index.js";
import {drainQueue} from "../packages/worker/src/index.js";
import {Pool} from "pg";
const A="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const fixture=(name:string)=>readFileSync(new URL("../fixtures/"+name,import.meta.url),"utf8");
test("real PG16 Phase2 importer: all 4 formats, idempotency, versions, diff, RLS, original assessment, adversarial transactions",async()=>{
 await migrate();
 const app=await makeApp();
 const req=(method:"GET"|"POST"|"PATCH",url:string,payload?:object,which="local-test-token-alpha",key?:string)=>
   app.inject({method,url,headers:{authorization:"Bearer "+which,...(key?{"idempotency-key":key}:{})},payload});
 const suffix=crypto.randomUUID().slice(0,8);
 try{
  const target=await req("POST","/v1/targets",{name:"Discovery "+suffix,baseUrl:"https://discover-"+suffix+".fixture.invalid",environment:"SYNTHETIC"});
  assert.equal(target.statusCode,201,target.body);
  const targetId=target.json().id as string;
  const endpoint="/v2/targets/"+targetId+"/specifications/imports";
  const upload=(filename:string,content:string,key?:string,who?:string)=>
    req("POST",endpoint,{filename,content},who,key??"disc-"+crypto.randomUUID());
  const p1=await upload("billing-v1.json",fixture("phase2-openapi30-v1.json"));
  assert.equal(p1.statusCode,201,p1.body);
  assert.equal(p1.json().format,"OPENAPI_3_0");
  assert.equal(p1.json().version,1);
  assert.equal(p1.json().operationCount,2);
  assert.equal(p1.json().assessmentEligible,false);
  const spec1=p1.json().specificationId as string;
  assert.equal((await req("GET","/v2/specifications/"+spec1)).json().metadata.title,"Billing Demo");
  const op1=await req("GET","/v2/specifications/"+spec1+"/operations?limit=20");
  assert.equal(op1.statusCode,200,op1.body);assert.equal(op1.json().length,2);
  assert.equal((await req("GET","/v2/specifications/"+spec1+"/operations?method=GET&search=bills")).json().length,1);
  assert.equal((await req("GET","/v2/specifications/"+spec1+"/schemes")).json().BearerAuth.type,"http");
  const exact=await req("GET","/v2/specifications/"+spec1+"/operations/"+encodeURIComponent("GET /bills"));
  assert.equal(exact.statusCode,200);assert.equal(exact.json().parameters[0].name,"limit");
  assert.equal((await req("GET","/v2/specifications/"+spec1+"/coverage")).json().assessmentEligible,false);
  assert.equal((await req("POST","/v2/targets/"+targetId+"/specifications/"+spec1+"/select",{expectedSelectedId:null})).statusCode,409);
  assert.equal((await req("POST","/v1/targets/"+targetId+"/assessments",{specificationId:spec1,mode:"SPEC_ONLY"},"local-test-token-alpha","assess-"+crypto.randomUUID())).statusCode,409);
  const p2=await upload("billing-v2.json",fixture("phase2-openapi30-v2.json"));
  assert.equal(p2.statusCode,201,p2.body);assert.equal(p2.json().version,2);
  const spec2=p2.json().specificationId as string;
  const versions=await req("GET","/v2/targets/"+targetId+"/specifications");
  assert.deepEqual(versions.json().map((x:{version:number})=>x.version),[2,1]);
  const compare=await req("POST","/v2/targets/"+targetId+"/specifications/compare",{fromSpecificationId:spec1,toSpecificationId:spec2});
  assert.equal(compare.statusCode,200,compare.body);
  assert.deepEqual(compare.json().added,["POST /bills"]);assert.deepEqual(compare.json().removed,["GET /status"]);
  assert.deepEqual(compare.json().changed[0].fields,["auth"]);
  const fixedKey="retry-"+crypto.randomUUID();
  const once=await upload("billing.json",fixture("phase2-openapi30-v1.json"),fixedKey);
  assert.equal(once.statusCode,201,once.body);assert.equal(once.json().deduplicated,true);
  assert.equal(once.json().specificationId,spec1);
  const sameKey=await upload("billing.json",fixture("phase2-openapi30-v1.json"),fixedKey);
  assert.equal(sameKey.statusCode,200,sameKey.body);assert.equal(sameKey.json().specificationId,spec1);
  const keyConflict=await upload("billing.json",fixture("phase2-openapi30-v2.json"),fixedKey);
  assert.equal(keyConflict.statusCode,409);
  const concurrent=await Promise.all(Array.from({length:3},()=>upload("billing.json",fixture("phase2-openapi30-v2.json"))));
  assert.ok(concurrent.every(x=>x.statusCode===201));assert.ok(concurrent.every(x=>x.json().specificationId===spec2));
  const post=await upload("collection.json",fixture("phase2-postman21.json"));
  assert.equal(post.statusCode,201,post.body);assert.equal(post.json().format,"POSTMAN_2_1");
  const postId=post.json().specificationId as string;
  const postOps=(await req("GET","/v2/specifications/"+postId+"/operations")).json() as {auth:{state:string};folder:string[];key:string}[];
  assert.equal(postOps.length,2);assert.equal(postOps[0]?.auth.state,"INHERITED");assert.equal(postOps[1]?.auth.state,"EXPLICIT_NONE");
  assert.deepEqual(postOps[0]?.folder,["Billing"]);
  const postRaw=await withTenant(A,async tx=>(await tx.query("SELECT raw_spec FROM api_specifications WHERE id=$1",[postId])).rows[0].raw_spec as string);
  assert.ok(!postRaw.includes("test-secret-DO-NOT-PERSIST"));
  assert.ok(!postRaw.includes("pm.environment.set"));
  assert.ok(!postRaw.includes("Bearer secret-real"));
  const o31=await upload("customers.yaml",fixture("phase2-openapi31.yaml"));
  assert.equal(o31.statusCode,201,o31.body);assert.equal(o31.json().format,"OPENAPI_3_1");
  const assessSpec=o31.json().specificationId as string;
  const swagger=await upload("swagger.yaml",fixture("valid-swagger.yaml"));
  assert.equal(swagger.statusCode,201,swagger.body);assert.equal(swagger.json().format,"SWAGGER_2");
  assert.equal((await req("GET","/v2/targets/"+targetId+"/specifications")).json().length,5);
  const selected=await req("POST","/v2/targets/"+targetId+"/specifications/"+assessSpec+"/select",{expectedSelectedId:null});
  assert.equal(selected.statusCode,200,selected.body);
  assert.equal(selected.json().networkRequestsAuthorized,0);
  assert.equal((await req("POST","/v2/targets/"+targetId+"/specifications/"+swagger.json().specificationId+"/select",{expectedSelectedId:null})).statusCode,409);
  const selectedAgain=await req("POST","/v2/targets/"+targetId+"/specifications/"+swagger.json().specificationId+"/select",{expectedSelectedId:assessSpec});
  assert.equal(selectedAgain.statusCode,200,selectedAgain.body);
  const wrongTenant="local-test-token-beta";
  for(const url of [
   "/v2/targets/"+targetId+"/specifications","/v2/targets/"+targetId+"/specifications/imports",
   "/v2/specifications/"+spec1,"/v2/specifications/"+spec1+"/operations",
   "/v2/specifications/"+spec1+"/schemes","/v2/specifications/"+spec1+"/coverage"
  ])assert.equal((await req("GET",url,undefined,wrongTenant)).statusCode,404,url);
  assert.equal((await upload("collection.json",fixture("phase2-postman21.json"),"foreign-"+crypto.randomUUID(),wrongTenant)).statusCode,404);
  assert.equal((await req("POST","/v2/targets/"+targetId+"/specifications/compare",{fromSpecificationId:spec1,toSpecificationId:spec2},wrongTenant)).statusCode,404);
  const invalid=await upload("broken.json","{SECRET_EXFILTRATION_DO_NOT_ECHO");
  assert.equal(invalid.statusCode,422,invalid.body);
  assert.equal(invalid.json().errorCode,"INVALID_JSON");assert.ok(!invalid.body.includes("SECRET_EXFILTRATION_DO_NOT_ECHO"));
  const failed=(await req("GET",endpoint+"/"+invalid.json().id)).json();
  assert.deepEqual(failed.events.map((x:{state:string})=>x.state),["RECEIVED","VALIDATING","FAILED"]);
  assert.equal(failed.specificationId,null);
  const badExternal=await upload("badref.json",fixture("invalid-remote-ref.json"));
  assert.equal(badExternal.statusCode,422,badExternal.body);
  const changed=await upload("recovery.json",fixture("secure.openapi.json"));
  assert.equal(changed.statusCode,201,changed.body);
  const total=await withTenant(A,async tx=>(await tx.query("SELECT count(*)::int AS n FROM api_spec_inventories WHERE target_id=$1",[targetId])).rows[0].n as number);
  assert.equal(total,6);
  // Database-side injected failure AFTER the first normalized operation insert:
  // rollback must leave zero partially published authoritative inventories.
  const privileged=new Pool({connectionString:process.env.MIGRATION_DATABASE_URL,max:1});
  const injectionContent=JSON.parse(fixture("phase2-openapi30-v2.json"));
  injectionContent.info.version="3.0.0";
  const injectionText=JSON.stringify(injectionContent),injectionKey="atomic-fail-"+crypto.randomUUID();
  try{
   await privileged.query("CREATE OR REPLACE FUNCTION public.phase02_test_injected_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.operation_key='POST /bills' THEN RAISE EXCEPTION 'INJECTED_DB_FAILURE'; END IF; RETURN NEW; END $$");
   await privileged.query("CREATE TRIGGER phase02_test_failure BEFORE INSERT ON public.api_operations FOR EACH ROW EXECUTE FUNCTION public.phase02_test_injected_failure()");
   const injection=await upload("injected.json",injectionText,injectionKey);
   assert.equal(injection.statusCode,500,injection.body);
   assert.ok(!injection.body.includes("INJECTED_DB_FAILURE"),"Internal database failure must remain redacted");
   const existingAfterFailure=await withTenant(A,async tx=>(await tx.query("SELECT count(*)::int AS n FROM api_spec_inventories WHERE target_id=$1",[targetId])).rows[0].n as number);
   assert.equal(existingAfterFailure,6,"Failed commit cannot publish partial inventory");
   const failedRows=await withTenant(A,async tx=>(await tx.query("SELECT count(*)::int AS n FROM api_spec_imports WHERE target_id=$1 AND idempotency_key=$2",[targetId,injectionKey])).rows[0].n as number);
   assert.equal(failedRows,0,"Transaction failure leaves no half-committed job");
  }finally{
   await privileged.query("DROP TRIGGER IF EXISTS phase02_test_failure ON public.api_operations");
   await privileged.query("DROP FUNCTION IF EXISTS public.phase02_test_injected_failure()");
   await privileged.end();
  }
  const recovered=await upload("injected.json",injectionText,injectionKey);
  assert.equal(recovered.statusCode,201,recovered.body);
  assert.equal(recovered.json().version,7);

  const queued=await req("POST","/v1/targets/"+targetId+"/assessments",{specificationId:assessSpec,mode:"SPEC_ONLY"},"local-test-token-alpha","phase2-"+crypto.randomUUID());
  assert.equal(queued.statusCode,201,queued.body);
  assert.equal(await drainQueue(),1);
  const report=await req("GET","/v1/assessments/"+queued.json().id+"/report");
  assert.equal(report.statusCode,200,report.body);
  const reportText=report.body;
  const history=(await req("GET","/v2/specifications/"+assessSpec)).json();
  assert.equal(history.rawFingerprint,o31.json().rawFingerprint);
  assert.equal((await req("GET","/v1/assessments/"+queued.json().id+"/report")).body,reportText);
  const phases=(await withTenant(A,async tx=>tx.query("SELECT version FROM api_schema_migrations ORDER BY version"))).rows.map(x=>x.version);
  assert.deepEqual(phases,["001","002","003","004","005","006","007","008","009","010","011","012","013","014","015","016"],"Phase12 preserves all original 001–015 migration versions unchanged and appends only forward-only migration 016");
  await assert.rejects(()=>withTenant(A,async tx=>tx.query("DELETE FROM api_spec_inventories WHERE specification_id=$1",[spec1])),/IMMUTABLE|PHASE1_IMMUTABLE/);
  await assert.rejects(()=>withTenant(A,async tx=>tx.query("UPDATE api_spec_inventories SET snapshot='{}'::jsonb WHERE specification_id=$1",[spec1])),/IMMUTABLE_INVENTORY_CONTENT/);
  await assert.rejects(()=>withTenant(A,async tx=>tx.query("UPDATE api_inventory_operations SET path='/evil' WHERE specification_id=$1",[spec1])),/PHASE1_IMMUTABLE_HISTORY/);
  const current=(await req("GET","/v1/targets/"+targetId)).json();
  const suspended=await req("POST","/v1/targets/"+targetId+"/lifecycle",{revision:current.revision,action:"SUSPEND"});
  assert.equal(suspended.statusCode,200);
  assert.equal((await upload("postman.json",fixture("phase2-postman21.json"))).statusCode,409);
  assert.equal((await req("POST","/v2/targets/"+targetId+"/specifications/"+assessSpec+"/select",{expectedSelectedId:swagger.json().specificationId})).statusCode,409);
  assert.equal((await req("GET","/v2/specifications/"+assessSpec)).statusCode,200);
 }finally{await app.close();await pool.end();await workerPool.end();}
});
