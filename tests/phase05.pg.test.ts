import {test} from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {randomUUID} from "node:crypto";
import {Pool} from "pg";
import {makeApp} from "../packages/service/src/app.js";
import {migrate,pool,workerPool,withTenant,withWorkerTenant,claimJob} from "../packages/database/src/index.js";
import {drainQueue,processOneJob} from "../packages/worker/src/index.js";
const A="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const fixture=(name:string)=>readFileSync(new URL("../fixtures/"+name,import.meta.url),"utf8");
test("Phase05 real PostgreSQL: unified cross-engine history, immutable export, coverage, evidence, comparison and tenant negatives",async()=>{
 await migrate();
 const app=await makeApp(),suffix=randomUUID().slice(0,8);
 const call=(method:"GET"|"POST",url:string,payload?:unknown,token="local-test-token-alpha",key?:string)=>
  app.inject({method,url,headers:{authorization:"Bearer "+token,...(key?{"idempotency-key":key}:{})},payload:payload as object|undefined});
 try{
  const target=await call("POST","/v1/targets",{name:"Phase05 "+suffix,baseUrl:"https://phase05-"+suffix+".fixture.invalid",environment:"SYNTHETIC"});
  assert.equal(target.statusCode,201,target.body);
  const tid=target.json().id as string;
  const importSpec=async(name:string)=>{
   const response=await call("POST","/v2/targets/"+tid+"/specifications/imports",{filename:name,content:fixture(name)},"local-test-token-alpha","phase05-import-"+randomUUID());
   assert.equal(response.statusCode,201,response.body);
   return response.json().specificationId as string;
  };
  const firstSpec=await importSpec("phase2-openapi30-v1.json");

  const rich=await withTenant(A,tx=>tx.query("SELECT snapshot FROM api_rich_inventories WHERE specification_id=$1",[firstSpec]));
  assert.equal(rich.rowCount,1);
  assert.equal(rich.rows[0].snapshot.normalizationVersion,"phase05-v2");
  assert.equal((await withTenant("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",tx=>tx.query("SELECT 1 FROM api_rich_inventories WHERE specification_id=$1",[firstSpec]))).rowCount,0);
  const v2Body={specificationId:firstSpec,engineVersion:"inventory-v2",mode:"SPEC_ONLY"};
  const key="rich-"+randomUUID();
  const initial=await call("POST","/v5/targets/"+tid+"/assessments",v2Body,"local-test-token-alpha",key);
  assert.equal(initial.statusCode,201,initial.body);
  const richId=initial.json().id as string;
  assert.equal(initial.json().networkRequestsAuthorized,0);
  assert.equal((await call("POST","/v5/targets/"+tid+"/assessments",v2Body,"local-test-token-alpha",key)).json().id,richId);
  assert.equal((await call("POST","/v5/targets/"+tid+"/assessments",{...v2Body,engineVersion:"auth-fixture-v1"},"local-test-token-alpha","deny-"+randomUUID())).statusCode,400);
  assert.equal((await call("POST","/v5/targets/"+tid+"/assessments",v2Body,"local-test-token-beta","foreign-"+randomUUID())).statusCode,404);
  const contenders=await Promise.all(Array.from({length:8},()=>processOneJob()));
  assert.equal(contenders.filter(Boolean).length,1);
  assert.equal((await call("GET","/v5/assessments/"+richId)).json().status,"COMPLETED");
  const richReport=(await call("GET","/v5/assessments/"+richId+"/report")).json();
  assert.equal(richReport.immutableReport.engineVersion,"inventory-v2");
  assert.equal(richReport.immutableReport.coverage.length,28);
  assert.equal(richReport.immutableReport.coverage.find((x:{ruleId:string})=>x.ruleId==="API03_AUTH_OVERRIDE_WEAKENS").status,"EVALUATED");
  assert.equal(richReport.verifiedFixed,false);
  await assert.rejects(()=>withTenant(A,tx=>tx.query("UPDATE api_rich_inventories SET rich_fingerprint=$2 WHERE specification_id=$1",[firstSpec,"0".repeat(64)])),/PHASE1_IMMUTABLE|permission denied/);
  const cancellation=await call("POST","/v5/targets/"+tid+"/assessments",v2Body,"local-test-token-alpha","cancel-"+randomUUID());
  assert.equal(cancellation.statusCode,201);
  const cancelId=cancellation.json().id as string;
  assert.equal((await call("POST","/v5/assessments/"+cancelId+"/cancel")).statusCode,200);
  assert.equal((await call("POST","/v5/assessments/"+cancelId+"/cancel")).statusCode,409);
  assert.equal((await call("GET","/v5/assessments/"+cancelId)).json().status,"CANCELLED");
  const stale=await call("POST","/v5/targets/"+tid+"/assessments",v2Body,"local-test-token-alpha","stale-"+randomUUID());
  const staleId=stale.json().id as string;
  const lease=await claimJob();
  assert.equal(lease?.assessment_id,staleId);
  await withWorkerTenant(A,async tx=>{await tx.query("UPDATE api_queue.api_assessment_queue SET locked_until=now()-interval '1 minute' WHERE assessment_id=$1",[staleId]);});
  assert.equal(await processOneJob(),true);
  assert.equal((await call("GET","/v5/assessments/"+staleId)).json().status,"COMPLETED");
  assert.equal((await call("POST","/v5/assessments/compare",{fromAssessmentId:richId,toAssessmentId:staleId})).json().comparable,true);
  // Controlled PostgreSQL fault during report INSERT must roll back every evidence,
  // finding and rule result in the publication transaction. The failed assessment
  // remains auditable and a fresh assessment can recover without manual repair.
  const injected=await call("POST","/v5/targets/"+tid+"/assessments",v2Body,"local-test-token-alpha","fault-"+randomUUID());
  assert.equal(injected.statusCode,201,injected.body);
  const faultId=injected.json().id as string;
  const admin=new Pool({connectionString:process.env.MIGRATION_DATABASE_URL,max:1});
  try{
    await admin.query("CREATE FUNCTION public.phase05_test_fault() RETURNS trigger LANGUAGE plpgsql AS $ BEGIN IF NEW.assessment_id = '"+faultId+"'::uuid THEN RAISE EXCEPTION 'PHASE05_INJECTED_PUBLICATION_FAILURE'; END IF; RETURN NEW; END $");
    await admin.query("CREATE TRIGGER phase05_inject BEFORE INSERT ON public.api_reports FOR EACH ROW EXECUTE FUNCTION public.phase05_test_fault()");
    assert.equal(await processOneJob(),true);
    assert.equal((await call("GET","/v5/assessments/"+faultId)).json().status,"FAILED");
    const outputs=await withTenant(A,async tx=>Promise.all([
      tx.query("SELECT count(*)::int AS n FROM api_reports WHERE assessment_id=$1",[faultId]),
      tx.query("SELECT count(*)::int AS n FROM api_findings WHERE assessment_id=$1",[faultId]),
      tx.query("SELECT count(*)::int AS n FROM api_evidence WHERE assessment_id=$1",[faultId]),
      tx.query("SELECT count(*)::int AS n FROM api_rule_results WHERE assessment_id=$1",[faultId])
    ]));
    assert.deepEqual(outputs.map(x=>x.rows[0].n),[0,0,0,0],"publication must be atomic");
    assert.equal((await withWorkerTenant(A,tx=>tx.query("SELECT count(*)::int AS n FROM api_queue.api_assessment_queue WHERE assessment_id=$1",[faultId]))).rows[0].n,0);
  }finally{
    await admin.query("DROP TRIGGER IF EXISTS phase05_inject ON public.api_reports");
    await admin.query("DROP FUNCTION IF EXISTS public.phase05_test_fault()");
    await admin.end();
  }
  const recovery=await call("POST","/v5/targets/"+tid+"/assessments",v2Body,"local-test-token-alpha","recovered-"+randomUUID());
  assert.equal(recovery.statusCode,201);
  assert.equal(await processOneJob(),true);
  assert.equal((await call("GET","/v5/assessments/"+recovery.json().id)).json().status,"COMPLETED");

  const firstJob=await call("POST","/v3/targets/"+tid+"/assessments",{specificationId:firstSpec,mode:"SPEC_ONLY",engineVersion:"inventory-v1"},"local-test-token-alpha","phase05-run-"+randomUUID());
  assert.equal(firstJob.statusCode,201,firstJob.body);
  const firstId=firstJob.json().id as string;
  assert.equal((await call("GET","/v5/assessments/"+firstId+"/report")).statusCode,409);
  assert.equal(await drainQueue(),1);
  const firstDetail=await call("GET","/v5/assessments/"+firstId);
  assert.equal(firstDetail.statusCode,200,firstDetail.body);
  assert.equal(firstDetail.json().engineVersion,"inventory-v1");
  assert.equal(firstDetail.json().status,"COMPLETED");
  const list=await call("GET","/v5/assessments?targetId="+tid+"&engineVersion=inventory-v1");
  assert.equal(list.statusCode,200,list.body);
  assert.ok(list.json().some((x:{id:string})=>x.id===firstId));
  const coverage=await call("GET","/v5/assessments/"+firstId+"/coverage");
  assert.equal(coverage.statusCode,200,coverage.body);
  assert.equal(coverage.json().rules.length,28);
  assert.equal(coverage.json().runtimeValidation,false);
  const findings=await call("GET","/v5/assessments/"+firstId+"/findings?limit=25");
  assert.equal(findings.statusCode,200,findings.body);
  assert.ok(findings.json().length>0);
  const item=findings.json()[0] as {id:string;ruleId:string;observationType:string};
  assert.equal(item.observationType,"SPEC_OBSERVATION");
  const detail=await call("GET","/v5/assessments/"+firstId+"/findings/"+item.id);
  assert.equal(detail.statusCode,200,detail.body);
  assert.equal(detail.json().ruleId,item.ruleId);
  assert.ok(detail.json().sourcePointer);
  assert.equal(detail.json().engineVersion,"inventory-v1");
  const select=await call("GET","/v5/assessments/"+firstId+"/findings?ruleId="+item.ruleId);
  assert.equal(select.statusCode,200,select.body);
  assert.ok(select.json().every((x:{ruleId:string})=>x.ruleId===item.ruleId));
  assert.equal((await call("GET","/v5/assessments/"+firstId+"/findings?impact=UNTRUSTED")).statusCode,400);
  const report=await call("GET","/v5/assessments/"+firstId+"/report");
  assert.equal(report.statusCode,200,report.body);
  assert.equal(report.json().schemaVersion,"phase05-report-v1");
  assert.equal(report.json().provenance.engineVersion,"inventory-v1");
  assert.equal(report.json().verifiedFixed,false);
  const exportData=await call("GET","/v5/assessments/"+firstId+"/export");
  assert.equal(exportData.statusCode,200,exportData.body);
  assert.match(String(exportData.headers["content-disposition"]),/attachment;/);
  assert.equal(exportData.json().immutableReport.observationCount,report.json().immutableReport.observationCount);
  assert.equal((await call("GET","/v5/assessments/"+firstId+"/export",undefined,"local-test-token-beta")).statusCode,404);
  assert.equal((await call("GET","/v5/assessments/"+firstId+"/findings",undefined,"local-test-token-beta")).statusCode,404);
  assert.equal((await call("GET","/v5/assessments/"+firstId+"/findings/"+item.id,undefined,"local-test-token-beta")).statusCode,404);
  assert.equal((await call("GET","/v5/assessments/"+firstId+"/coverage",undefined,"local-test-token-beta")).statusCode,404);
  assert.equal((await call("GET","/v5/assessments?targetId="+tid,undefined,"local-test-token-beta")).statusCode,404);
  const secondSpec=await importSpec("phase2-openapi30-v2.json");
  const secondJob=await call("POST","/v3/targets/"+tid+"/assessments",{specificationId:secondSpec,mode:"SPEC_ONLY",engineVersion:"inventory-v1"},"local-test-token-alpha","phase05-run-"+randomUUID());
  assert.equal(secondJob.statusCode,201,secondJob.body);
  assert.equal(await drainQueue(),1);
  const secondId=secondJob.json().id as string;
  const compare=await call("POST","/v5/assessments/compare",{fromAssessmentId:firstId,toAssessmentId:secondId});
  assert.equal(compare.statusCode,200,compare.body);
  assert.equal(compare.json().comparable===true||compare.json().reason==="RULE_VERSION_OR_COVERAGE_INCOMPATIBLE",true);
  assert.match(compare.body,/NOT VERIFIED_FIXED/);
  assert.equal((await call("POST","/v5/assessments/compare",{fromAssessmentId:firstId,toAssessmentId:secondId},"local-test-token-beta")).statusCode,404);
  assert.equal((await call("POST","/v5/assessments/compare",{fromAssessmentId:firstId,toAssessmentId:firstId})).statusCode,400);
  assert.deepEqual((await call("GET","/v5/assessments/"+firstId+"/report")).json().immutableReport,report.json().immutableReport);
  await assert.rejects(()=>withTenant(A,tx=>tx.query("UPDATE api_reports SET projection='{}'::jsonb WHERE assessment_id=$1",[firstId])),/PHASE1_IMMUTABLE/);
  const migrations=await pool.query("SELECT version FROM api_schema_migrations WHERE version='007'");
  assert.equal(migrations.rowCount,1);
  const rls=await pool.query("SELECT relrowsecurity,relforcerowsecurity FROM pg_class WHERE oid='public.api_findings'::regclass");
  assert.equal(rls.rows[0].relrowsecurity,true);
  assert.equal(rls.rows[0].relforcerowsecurity,true);
  const engines=await call("GET","/v5/engines");
  assert.equal(engines.statusCode,200);
  assert.equal(engines.json().maxRequests,0);
  assert.equal(engines.json().options.length,4);
 }finally{await app.close();await pool.end();await workerPool.end();}
});
