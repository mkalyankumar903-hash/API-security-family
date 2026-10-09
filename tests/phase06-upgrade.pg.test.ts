import {test} from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {randomUUID} from "node:crypto";
import {Pool} from "pg";

test("Phase06 populated Phase05 -> migration009 and hardening010 upgrade preserves targets, inventory-v2, evidence, findings and immutable reports",async()=>{
 const root=process.env.MIGRATION_DATABASE_URL;
 if(!root)throw new Error("MIGRATION_DATABASE_URL_REQUIRED");
 const admin=new Pool({connectionString:root,max:1});
 const name="phase06_upgrade_"+randomUUID().replaceAll("-","").slice(0,18);
 const url=new URL(root);url.pathname="/"+name;
 const clone=new Pool({connectionString:url.toString(),max:1});
 let created=false;
 try{
  await admin.query("CREATE DATABASE "+name);
  created=true;
  await clone.query("CREATE TABLE api_schema_migrations(version text PRIMARY KEY)");
  for(let i=0;i<8;i++){
   const files=[
    "001_phase0.sql","002_queue_isolation.sql","003_phase1_target_onboarding.sql",
    "004_phase2_offline_discovery.sql","005_phase3_deterministic_detection.sql",
    "006_phase4_authenticated_fixture.sql","007_phase5_unified_assessment.sql",
    "008_phase5_rich_offline.sql"
   ];
   const sql=readFileSync(new URL("../packages/database/migrations/"+files[i],import.meta.url),"utf8");
   await clone.query(sql);
   await clone.query("INSERT INTO api_schema_migrations(version) VALUES($1)",[String(i+1).padStart(3,"0")]);
  }
  const tenant="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
  const target=randomUUID(),spec=randomUUID(),assessment=randomUUID(),evidence=randomUUID(),finding=randomUUID(),report=randomUUID();
  await clone.query("INSERT INTO api_targets(id,tenant_id,name,base_url,environment) VALUES($1,$2,'Preserved Phase05','https://upgrade.fixture.invalid','SYNTHETIC')",
   [target,tenant]);
  await clone.query("INSERT INTO api_specifications(id,tenant_id,target_id,filename,format,fingerprint,raw_spec) VALUES($1,$2,$3,'old.json','OPENAPI_3_0',$4,'{}')",
   [spec,tenant,target,"a".repeat(64)]);
  await clone.query("INSERT INTO api_spec_inventories(specification_id,tenant_id,target_id,version_number,original_format,raw_fingerprint,normalized_fingerprint,normalization_version,snapshot,assessment_source,coverage,selected) VALUES($1,$2,$3,1,'OPENAPI_3_0',$4,$5,'phase02-v1','{}'::jsonb,'OpenAPI','SUPPORTED_PROFILE',true)",
   [spec,tenant,target,"a".repeat(64),"b".repeat(64)]);
  await clone.query("INSERT INTO api_rich_inventories(specification_id,tenant_id,target_id,raw_fingerprint,phase02_fingerprint,rich_fingerprint,snapshot) VALUES($1,$2,$3,$4,$5,$6,'{}'::jsonb)",
   [spec,tenant,target,"a".repeat(64),"b".repeat(64),"c".repeat(64)]);
  await clone.query("INSERT INTO api_assessments(id,tenant_id,target_id,specification_id,status,mode,idempotency_key,engine_version) VALUES($1,$2,$3,$4,'COMPLETED','SPEC_ONLY','pre-phase6-immutable-report','legacy-v1')",
   [assessment,tenant,target,spec]);
  await clone.query("INSERT INTO api_evidence(id,tenant_id,assessment_id,fingerprint,pointer,content_json) VALUES($1,$2,$3,$4,'/paths','{}'::jsonb)",
   [evidence,tenant,assessment,"d".repeat(64)]);
  await clone.query("INSERT INTO api_findings(id,tenant_id,assessment_id,evidence_id,rule_id,category,explanation,remediation,confidence,validation_level,review_required) VALUES($1,$2,$3,$4,'BASELINE','SPEC','Old observation','Review','SPEC_OBSERVATION','SPEC_ONLY',true)",
   [finding,tenant,assessment,evidence]);
  await clone.query("INSERT INTO api_reports(id,tenant_id,assessment_id,projection) VALUES($1,$2,$3,$4::jsonb)",
   [report,tenant,assessment,JSON.stringify({phase:5,history:"preserved"})]);
  const migrate9=readFileSync(new URL("../packages/database/migrations/009_phase6_pt_safe_execution.sql",import.meta.url),"utf8");
  await clone.query("BEGIN");
  try{
   await clone.query(migrate9);
   await clone.query("INSERT INTO api_schema_migrations(version) VALUES('009')");
   await clone.query(readFileSync(new URL("../packages/database/migrations/010_phase6_permit_storage_hardening.sql",import.meta.url),"utf8"));
   await clone.query("INSERT INTO api_schema_migrations(version) VALUES('010')");
   await clone.query("COMMIT");
  }catch(e){await clone.query("ROLLBACK");throw e;}
  for(const [table,where,id] of [
   ["api_targets","id",target],["api_specifications","id",spec],
   ["api_spec_inventories","specification_id",spec],["api_rich_inventories","specification_id",spec],
   ["api_assessments","id",assessment],["api_evidence","id",evidence],
   ["api_findings","id",finding],["api_reports","id",report]
  ]){
   const row=await clone.query("SELECT count(*)::int AS n FROM "+table+" WHERE "+where+"=$1",[id]);
   assert.equal(row.rows[0].n,1,table);
  }
  const history=await clone.query("SELECT projection FROM api_reports WHERE id=$1",[report]);
  assert.deepEqual(history.rows[0].projection,{phase:5,history:"preserved"});
  const kinds=await clone.query("SELECT engine_version FROM api_assessments WHERE id=$1",[assessment]);
  assert.equal(kinds.rows[0].engine_version,"legacy-v1");
  const pt=await clone.query("SELECT count(*)::int AS n FROM api_pt_permits");
  assert.equal(pt.rows[0].n,0,"no implicit synthetic permission after upgrade");
  const security=await clone.query("SELECT relrowsecurity,relforcerowsecurity FROM pg_class WHERE oid='public.api_pt_permits'::regclass");
  assert.equal(security.rows[0].relrowsecurity,true);
  assert.equal(security.rows[0].relforcerowsecurity,true);
  await assert.rejects(()=>clone.query("UPDATE api_reports SET projection='{}'::jsonb WHERE id=$1",[report]),/PHASE1_IMMUTABLE/);
  assert.equal((await clone.query("SELECT count(*)::int AS n FROM api_schema_migrations")).rows[0].n,10);
 }finally{
  await clone.end();
  if(created)await admin.query("DROP DATABASE "+name);
  await admin.end();
 }
});
