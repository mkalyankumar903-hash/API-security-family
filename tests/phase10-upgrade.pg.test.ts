import {test} from "node:test";
import assert from "node:assert/strict";
import {randomUUID,createHash} from "node:crypto";
import {readFileSync} from "node:fs";
import {Pool} from "pg";

const MIGRATIONS=[
 "001_phase0.sql","002_queue_isolation.sql","003_phase1_target_onboarding.sql",
 "004_phase2_offline_discovery.sql","005_phase3_deterministic_detection.sql",
 "006_phase4_authenticated_fixture.sql","007_phase5_unified_assessment.sql",
 "008_phase5_rich_offline.sql","009_phase6_pt_safe_execution.sql",
 "010_phase6_permit_storage_hardening.sql","011_phase7_pt_detection.sql",
 "012_phase8_complete_pt_product.sql","013_phase9_deterministic_orchestrator.sql",
 "014_phase10_worker_execution_safety.sql"
];
const fingerprint=(rows:unknown)=>createHash("sha256").update(JSON.stringify(rows)).digest("hex");
test("Phase10 populated 013 -> 014: forward-only migration preserves historical report, evidence and queue",async()=>{
 const root=process.env.MIGRATION_DATABASE_URL;
 if(!root)throw new Error("MIGRATION_DATABASE_URL_REQUIRED");
 const admin=new Pool({connectionString:root,max:1});
 const name="phase10_upgrade_"+randomUUID().replaceAll("-","").slice(0,16);
 const parsed=new URL(root);parsed.pathname="/"+name;
 const db=new Pool({connectionString:parsed.toString(),max:1});
 let created=false;
 try{
  await admin.query("CREATE DATABASE "+name);created=true;
  await db.query("CREATE TABLE api_schema_migrations(version text PRIMARY KEY)");
  for(const [i,file] of MIGRATIONS.slice(0,13).entries()){
   await db.query("BEGIN");
   try{
    await db.query(readFileSync(new URL("../packages/database/migrations/"+file,import.meta.url),"utf8"));
    await db.query("INSERT INTO api_schema_migrations(version) VALUES($1)",[String(i+1).padStart(3,"0")]);
    await db.query("COMMIT");
   }catch(e){await db.query("ROLLBACK");throw e;}
  }
  const t="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
   target=randomUUID(),spec=randomUUID(),done=randomUUID(),pending=randomUUID(),report=randomUUID(),evidence=randomUUID();
  await db.query("INSERT INTO api_targets(id,tenant_id,name,base_url,environment) VALUES($1,$2,'Preserved offline target','https://historic-phase10.fixture.invalid','SYNTHETIC')",[target,t]);
  await db.query("INSERT INTO api_specifications(id,tenant_id,target_id,filename,format,fingerprint,raw_spec) VALUES($1,$2,$3,'historic.json','OPENAPI_3_0',$4,'{}')",[spec,t,target,"a".repeat(64)]);
  await db.query("INSERT INTO api_assessments(id,tenant_id,target_id,specification_id,status,mode,idempotency_key,engine_version) VALUES($1,$2,$3,$4,'COMPLETED','SPEC_ONLY','historic-worker-report','legacy-v1')",[done,t,target,spec]);
  await db.query("INSERT INTO api_assessments(id,tenant_id,target_id,specification_id,status,mode,idempotency_key,engine_version) VALUES($1,$2,$3,$4,'QUEUED','SPEC_ONLY','historic-worker-queued','legacy-v1')",[pending,t,target,spec]);
  await db.query("INSERT INTO api_evidence(id,tenant_id,assessment_id,fingerprint,pointer,content_json) VALUES($1,$2,$3,$4,'/history',$5::jsonb)",
   [evidence,t,done,"b".repeat(64),JSON.stringify({historical:true,source:"pre-phase10"})]);
  await db.query("INSERT INTO api_reports(id,tenant_id,assessment_id,projection) VALUES($1,$2,$3,$4::jsonb)",
   [report,t,done,JSON.stringify({schemaVersion:"legacy-offline-v1",syntheticOnly:true,immutable:true})]);
  await db.query("INSERT INTO api_queue.api_assessment_queue(assessment_id,tenant_id) VALUES($1,$2)",[pending,t]);

  // Multiple populated historical engine/mode combinations at 013, before
  // Phase10 metadata exists. Preserve each immutable report identity and
  // engine discriminator; the upgrade must not interpret these as new work.
  await db.query("INSERT INTO api_spec_inventories(specification_id,tenant_id,target_id,version_number,original_format,raw_fingerprint,normalized_fingerprint,normalization_version,snapshot,assessment_source,coverage,selected) VALUES($1,$2,$3,1,'OPENAPI_3_0',$4,$5,'phase02-v1','{}'::jsonb,'OpenAPI','SUPPORTED_PROFILE',true)",[spec,t,"a".repeat(64),"b".repeat(64)]);
  await db.query("INSERT INTO api_rich_inventories(specification_id,tenant_id,target_id,raw_fingerprint,phase02_fingerprint,rich_fingerprint,snapshot) VALUES($1,$2,$3,$4,$5,$6,'{}'::jsonb)",[spec,t,"a".repeat(64),"b".repeat(64),"c".repeat(64)]);
  for(const engine of ["legacy-v1","inventory-v1","auth-fixture-v1","inventory-v2",
   "pt-fixture-v1","pt-detection-v1","pt-orchestrator-v1"]){
   const id=randomUUID();
   const ptEngine=engine.startsWith("pt-");
   await db.query("INSERT INTO api_assessments(id,tenant_id,target_id,specification_id,status,mode,idempotency_key,engine_version) VALUES($1,$2,$3,$4,$5,$6,$7,$8)",[
    id,t,target,spec,ptEngine?"FAILED":"COMPLETED",ptEngine?"SYNTHETIC_PT_FIXTURE":"SPEC_ONLY",
    "historical-version-"+engine,engine]);
   if(!ptEngine){
    await db.query("INSERT INTO api_reports(id,tenant_id,assessment_id,projection) VALUES($1,$2,$3,$4::jsonb)",[
     randomUUID(),t,id,JSON.stringify({schemaVersion:"historical-"+engine,
      syntheticOnly:true,verifiedFixed:false,engineVersion:engine,customerNetworkRequests:0})]);
   }
  }
  const preVersions=await db.query("SELECT engine_version,mode,status FROM api_assessments ORDER BY engine_version,id");
  assert.ok(["legacy-v1","inventory-v1","auth-fixture-v1","inventory-v2",
   "pt-fixture-v1","pt-detection-v1","pt-orchestrator-v1"].every(x=>
   preVersions.rows.some(y=>y.engine_version===x)));

  const tables=[
   ["api_targets","id"],["api_specifications","id"],["api_assessments","id"],
   ["api_evidence","id"],["api_reports","id"],
   ["api_spec_inventories","specification_id"],["api_rich_inventories","specification_id"],
   ["api_queue.api_assessment_queue","assessment_id"]
  ] as const;
  const snapshots=new Map<string,{count:number;sha:string}>();
  for(const [table,key] of tables){
   const q=await db.query("SELECT * FROM "+table+" ORDER BY "+key);
   snapshots.set(table,{count:q.rowCount??0,sha:fingerprint(q.rows)});
  }
  assert.equal((await db.query("SELECT count(*)::int AS n FROM api_schema_migrations")).rows[0].n,13);
  await db.query("BEGIN");
  try{
   await db.query(readFileSync(new URL("../packages/database/migrations/014_phase10_worker_execution_safety.sql",import.meta.url),"utf8"));
   await db.query("INSERT INTO api_schema_migrations(version) VALUES('014')");
   await db.query("COMMIT");
  }catch(e){await db.query("ROLLBACK");throw e;}
  for(const [table,key] of tables){
   const q=await db.query("SELECT * FROM "+table+" ORDER BY "+key);
   assert.equal(q.rowCount,snapshots.get(table)!.count,table+" record count");
   if(table!=="api_queue.api_assessment_queue")
    assert.equal(fingerprint(q.rows),snapshots.get(table)!.sha,table+" existing row fingerprint");
   else{
    const row=q.rows[0];
    assert.equal(row.claim_generation,"0","old queue records receive safe default");
    assert.equal(row.claim_token,null);
    assert.equal(row.retry_count,0);
    assert.equal(row.assessment_id,pending);
   }
  }
  assert.equal((await db.query("SELECT count(*)::int AS n FROM api_schema_migrations")).rows[0].n,14);
  const postVersions=await db.query("SELECT engine_version,mode,status FROM api_assessments ORDER BY engine_version,id");
  assert.deepEqual(postVersions.rows,preVersions.rows,"all supported historical engines and statuses survive 013->014");
  assert.equal((await db.query("SELECT count(*)::int AS n FROM api_reports")).rows[0].n,5,
   "historical SPEC_ONLY immutable reports are not dropped, replayed or fabricated");
  await assert.rejects(()=>db.query("UPDATE api_reports SET projection='{}'::jsonb WHERE id=$1",[report]),/IMMUTABLE/i);
  const queues=await db.query("SELECT has_table_privilege('api_family','api_queue.api_assessment_queue','SELECT') AS read");
  assert.equal(queues.rows[0].read,false);
  const newTables=await db.query("SELECT relname,relforcerowsecurity FROM pg_class WHERE relname IN ('api_worker_attempts','api_worker_events','api_worker_quarantine')");
  assert.equal(newTables.rowCount,3);
  assert.ok(newTables.rows.every(x=>x.relforcerowsecurity));
 }finally{
  await db.end();
  if(created)await admin.query("DROP DATABASE "+name);
  await admin.end();
 }
});
