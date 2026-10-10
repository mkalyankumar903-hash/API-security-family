/** Populated Phase11 -> Phase13 real PostgreSQL migration preservation in a separate ephemeral DB. */
import {test} from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {createHash,randomUUID} from "node:crypto";
import {Pool} from "pg";
const files=[
 "001_phase0.sql","002_queue_isolation.sql","003_phase1_target_onboarding.sql",
 "004_phase2_offline_discovery.sql","005_phase3_deterministic_detection.sql",
 "006_phase4_authenticated_fixture.sql","007_phase5_unified_assessment.sql",
 "008_phase5_rich_offline.sql","009_phase6_pt_safe_execution.sql",
 "010_phase6_permit_storage_hardening.sql","011_phase7_pt_detection.sql",
 "012_phase8_complete_pt_product.sql","013_phase9_deterministic_orchestrator.sql",
 "014_phase10_worker_execution_safety.sql","015_phase11_complete_autonomous_api_vapt.sql",
 "016_phase12_unified_experience_reports.sql"];
const digest=(value:unknown)=>createHash("sha256").update(JSON.stringify(value)).digest("hex");
test("Phase13 populated 016→017 preserves original immutable reports, VAPT links, targets and private queue",async()=>{
 const root=process.env.MIGRATION_DATABASE_URL;
 if(!root)throw new Error("MIGRATION_DATABASE_URL_REQUIRED");
 const admin=new Pool({connectionString:root,max:1});
 const name="phase13_upgrade_"+randomUUID().replaceAll("-","").slice(0,16);
 const parsed=new URL(root);parsed.pathname="/"+name;
 const database=new Pool({connectionString:parsed.toString(),max:1});
 let created=false;
 try{
  await admin.query("CREATE DATABASE "+name);created=true;
  await database.query("CREATE TABLE public.api_schema_migrations(version text PRIMARY KEY)");
  for(const [index,file] of files.slice(0,15).entries()){
   await database.query("BEGIN");
   try{
    const sql=readFileSync(new URL("../packages/database/migrations/"+file,import.meta.url),"utf8");
    await database.query(sql);
    await database.query("INSERT INTO public.api_schema_migrations(version) VALUES($1)",[String(index+1).padStart(3,"0")]);
    await database.query("COMMIT");
   }catch(e){await database.query("ROLLBACK");throw e;}
  }
  const tenant="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",target=randomUUID(),
   spec=randomUUID(),offline=randomUUID(),parent=randomUUID(),queued=randomUUID(),reportId=randomUUID(),
   corr=randomUUID(),event=randomUUID(),fingerprint="a".repeat(64),stable="c".repeat(64);
  const offlineProjection={schemaVersion:"legacy-offline-v1",mode:"SPEC_ONLY",syntheticOnly:true,verifiedFixed:false};
  const parentProjection={schemaVersion:"autonomous-api-vapt-report-v1",assessmentId:parent,
   offlineAssessmentId:offline,mode:"OFFLINE_ONLY",status:"COMPLETED",
   planFingerprint:fingerprint,fullAuthorizedVaptCompleted:false,
   syntheticOnly:true,customerRuntimeVerified:false,verifiedFixed:false,customerNetworkRequests:0};
  await database.query("INSERT INTO public.api_targets(id,tenant_id,name,base_url,environment) VALUES($1,$2,'Preserved tenant','https://upgrade.fixture.invalid','SYNTHETIC')",[target,tenant]);
  await database.query("INSERT INTO public.api_specifications(id,tenant_id,target_id,filename,format,fingerprint,raw_spec) VALUES($1,$2,$3,'historic.json','OPENAPI_3_0',$4,'{}')",[spec,tenant,target,fingerprint]);
  for(const item of [
   {id:offline,status:"COMPLETED",engine:"legacy-v1",key:"historic-offline-2026"},
   {id:parent,status:"PROCESSING",engine:"autonomous-api-vapt-v1",key:"historic-vapt-parent"},
   {id:queued,status:"QUEUED",engine:"legacy-v1",key:"historic-private-queue"}]){
    const advanced=item.engine!=="legacy-v1";
    await database.query("INSERT INTO public.api_assessments(id,tenant_id,target_id,specification_id,status,mode,idempotency_key,engine_version,inventory_version,inventory_raw_fingerprint,inventory_fingerprint) VALUES($1,$2,$3,$4,$5,'SPEC_ONLY',$6,$7,$8,$9,$10)",
    [item.id,tenant,target,spec,item.status,item.key,item.engine,
     advanced?1:null,advanced?fingerprint:null,advanced?"b".repeat(64):null]);
  }
  await database.query("INSERT INTO public.api_reports(id,tenant_id,assessment_id,projection) VALUES($1,$2,$3,$4::jsonb)",
   [randomUUID(),tenant,offline,JSON.stringify(offlineProjection)]);
  await database.query("INSERT INTO public.api_vapt11_assessments(parent_assessment_id,tenant_id,target_id,specification_id,offline_assessment_id,mode,plan,fingerprint) VALUES($1,$2,$3,$4,$5,'OFFLINE_ONLY',$6::jsonb,$7)",
   [parent,tenant,target,spec,offline,JSON.stringify({schemaVersion:"autonomous-api-vapt-plan-v1",syntheticOnly:true,customerNetworkRequests:0}),fingerprint]);
  await database.query("INSERT INTO public.api_vapt11_correlations(id,tenant_id,parent_assessment_id,stable_key,source,projection) VALUES($1,$2,$3,$4,'SPEC_ONLY',$5::jsonb)",
   [corr,tenant,parent,stable,JSON.stringify({ruleId:"LEGACY_RETAINED",verifiedFixed:false})]);
  await database.query("INSERT INTO public.api_vapt11_reports(id,tenant_id,parent_assessment_id,projection,fingerprint) VALUES($1,$2,$3,$4::jsonb,$5)",
   [reportId,tenant,parent,JSON.stringify(parentProjection),digest(parentProjection)]);
  await database.query("UPDATE public.api_assessments SET status='COMPLETED',completed_at=clock_timestamp() WHERE id=$1",[parent]);
  await database.query("INSERT INTO public.api_vapt11_events(id,tenant_id,parent_assessment_id,code) VALUES($1,$2,$3,'PARENT_COMPLETED')",[event,tenant,parent]);
  await database.query("INSERT INTO api_queue.api_assessment_queue(assessment_id,tenant_id) VALUES($1,$2)",[queued,tenant]);
  const tables=["api_targets","api_specifications","api_assessments","api_reports",
   "api_vapt11_assessments","api_vapt11_correlations","api_vapt11_reports","api_vapt11_events"];
  async function snapshot(){
   const states:Record<string,unknown>={};
   for(const table of tables){
    const data=await database.query("SELECT * FROM public."+table+" ORDER BY 1");
    states[table]={count:data.rowCount,digest:digest(data.rows)};
   }
   const privateQueue=await database.query("SELECT assessment_id,tenant_id FROM api_queue.api_assessment_queue ORDER BY assessment_id");
   states.queue={count:privateQueue.rowCount,digest:digest(privateQueue.rows)};
   return states;
  }
  const before=await snapshot();
  await database.query("BEGIN");
  try{
   await database.query(readFileSync(new URL("../packages/database/migrations/016_phase12_unified_experience_reports.sql",import.meta.url),"utf8"));
   await database.query("INSERT INTO public.api_schema_migrations(version) VALUES('016')");
   await database.query("COMMIT");
  }catch(e){await database.query("ROLLBACK");throw e;}
  // Now retain populated historical Phase12 metadata across additive 016→017.
  const phase12ReportCount=(await database.query("SELECT count(*)::int AS n FROM public.api_v12_report_audit")).rows[0].n;
  await database.query("BEGIN");
  try{
   await database.query(readFileSync(new URL("../packages/database/migrations/017_phase13_commercial_entitlements_usage.sql",import.meta.url),"utf8"));
   await database.query("INSERT INTO public.api_schema_migrations(version) VALUES('017')");
   await database.query("COMMIT");
  }catch(e){await database.query("ROLLBACK");throw e;}
  assert.equal((await database.query("SELECT count(*)::int AS n FROM public.api_v12_report_audit")).rows[0].n,phase12ReportCount);
  const after=await snapshot();
  assert.deepEqual(after,before,"Migration 016 altered original historical reports or queue");
  const versions=await database.query("SELECT version FROM public.api_schema_migrations ORDER BY version");
  assert.equal(versions.rowCount,17);
  const report=await database.query("SELECT fingerprint,projection FROM public.api_vapt11_reports WHERE parent_assessment_id=$1",[parent]);
  assert.equal(report.rows[0].fingerprint,digest(parentProjection));
  assert.deepEqual(report.rows[0].projection,parentProjection);
  const metadata=await database.query("SELECT relname,relrowsecurity,relforcerowsecurity FROM pg_class WHERE relname LIKE 'api_v12_%' AND relkind='r'");
  assert.equal(metadata.rowCount,4);assert(metadata.rows.every(x=>x.relrowsecurity&&x.relforcerowsecurity));
  const v13=await database.query("SELECT relname,relrowsecurity,relforcerowsecurity FROM pg_class WHERE relname LIKE 'api_v13_%' AND relkind='r'");
  assert.equal(v13.rowCount,7);assert(v13.rows.every(x=>x.relrowsecurity&&x.relforcerowsecurity));
  const empty=await database.query("SELECT count(*)::int AS n FROM public.api_v12_annotations");
  assert.equal(empty.rows[0].n,0);
 }finally{
  await database.end();
  // Pool.end() drains the fixture's own connections; no administrator backend-kill.
  // A leaked fixture connection should fail DROP and reveal itself instead of generating
  // a late unhandled socket error after a nominally successful preservation assertion.
  if(created)await admin.query("DROP DATABASE "+name);
  await admin.end();
 }
});
