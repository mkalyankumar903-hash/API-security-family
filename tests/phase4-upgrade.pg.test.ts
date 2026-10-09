import {test} from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {Pool} from "pg";
const A="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const migration=(name:string)=>readFileSync(new URL("../packages/database/migrations/"+name,import.meta.url),"utf8");
test("Phase04 populated Phase03 → forward-only 006 preserves legacy+inventory immutable findings/reports",async()=>{
 const db="phase04_upgrade_"+crypto.randomUUID().replaceAll("-","").slice(0,12);
 const ownerUrl=new URL(process.env.MIGRATION_DATABASE_URL!),appUrl=new URL(process.env.DATABASE_URL!);
 const master=new Pool({connectionString:ownerUrl.toString()});ownerUrl.pathname="/"+db;appUrl.pathname="/"+db;
 let owner:Pool|undefined,service:Pool|undefined;
 const target=crypto.randomUUID(),spec=crypto.randomUUID(),legacy=crypto.randomUUID(),inventory=crypto.randomUUID();
 const hash="a".repeat(64),expected={from:"PHASE03_IMMUTABLE",sentinel:{preserved:true},history:123};
 try{
  await master.query("CREATE DATABASE "+db+" OWNER api_family");
  owner=new Pool({connectionString:ownerUrl.toString()});service=new Pool({connectionString:appUrl.toString()});
  const baseline=await service.connect();
  try{
   await baseline.query("BEGIN");await baseline.query("SELECT set_config('api.tenant_id',$1,true)",[A]);
   await baseline.query(migration("001_phase0.sql"));
   await baseline.query("CREATE TABLE api_schema_migrations(version text PRIMARY KEY)");
   await baseline.query("INSERT INTO api_schema_migrations(version) VALUES('001')");
   await baseline.query("INSERT INTO api_targets(id,tenant_id,name,base_url,environment) VALUES($1,$2,'Phase03 seeded','https://only-a-fixture.invalid','SYNTHETIC')",[target,A]);
   await baseline.query("INSERT INTO api_specifications(id,tenant_id,target_id,filename,format,fingerprint,raw_spec) VALUES($1,$2,$3,'old.json','OPENAPI_3_0',$4,'{}')",[spec,A,target,hash]);
   await baseline.query("INSERT INTO api_assessments(id,tenant_id,target_id,specification_id,status,mode,idempotency_key) VALUES($1,$2,$3,$4,'COMPLETED','SPEC_ONLY','upgrade-legacy-auth04')",[legacy,A,target,spec]);
   await baseline.query("INSERT INTO api_reports(id,tenant_id,assessment_id,projection) VALUES($1,$2,$3,$4::jsonb)",[crypto.randomUUID(),A,legacy,JSON.stringify(expected)]);
   await baseline.query("COMMIT");
  }catch(e){await baseline.query("ROLLBACK");throw e;}finally{baseline.release();}
  for(const [number,file] of [["002","002_queue_isolation.sql"],["003","003_phase1_target_onboarding.sql"],["004","004_phase2_offline_discovery.sql"],["005","005_phase3_deterministic_detection.sql"]] as const){
   await owner.query("BEGIN");
   try{await owner.query(migration(file));await owner.query("INSERT INTO api_schema_migrations(version) VALUES($1)",[number]);await owner.query("COMMIT");}
   catch(e){await owner.query("ROLLBACK");throw e;}
  }
  const t=await service.connect();
  try{
   await t.query("BEGIN");await t.query("SELECT set_config('api.tenant_id',$1,true)",[A]);
   await t.query("INSERT INTO api_spec_inventories(specification_id,tenant_id,target_id,version_number,original_format,raw_fingerprint,normalized_fingerprint,normalization_version,snapshot,assessment_source,coverage) VALUES($1,$2,$3,1,'OPENAPI_3_0',$4,$4,'phase02-v1',$5::jsonb,'{}','SUPPORTED_PROFILE')",
    [spec,A,target,hash,JSON.stringify({rawFingerprint:hash,normalizedFingerprint:hash})]);
   await t.query("INSERT INTO api_assessments(id,tenant_id,target_id,specification_id,status,mode,idempotency_key,engine_version,inventory_version,inventory_raw_fingerprint,inventory_fingerprint) VALUES($1,$2,$3,$4,'COMPLETED','SPEC_ONLY','upgrade-inventory-auth04','inventory-v1',1,$5,$5)",[inventory,A,target,spec,hash]);
   await t.query("INSERT INTO api_reports(id,tenant_id,assessment_id,projection) VALUES($1,$2,$3,$4::jsonb)",[crypto.randomUUID(),A,inventory,JSON.stringify(expected)]);
   await t.query("COMMIT");
  }catch(e){await t.query("ROLLBACK");throw e;}finally{t.release();}
  await owner.query("BEGIN");
  try{await owner.query(migration("006_phase4_authenticated_fixture.sql"));await owner.query("INSERT INTO api_schema_migrations(version) VALUES('006')");await owner.query("COMMIT");}
  catch(e){await owner.query("ROLLBACK");throw e;}
  const check=await service.connect();
  try{
   await check.query("BEGIN");await check.query("SELECT set_config('api.tenant_id',$1,true)",[A]);
   const reports=await check.query("SELECT a.engine_version,r.projection FROM api_reports r JOIN api_assessments a ON a.id=r.assessment_id WHERE a.id IN($1,$2) ORDER BY a.engine_version",[legacy,inventory]);
   assert.equal(reports.rowCount,2);
   assert.ok(reports.rows.some(r=>r.engine_version==="legacy-v1"));
   assert.ok(reports.rows.some(r=>r.engine_version==="inventory-v1"));
   for(const row of reports.rows)assert.deepEqual(row.projection,expected);
   await assert.rejects(()=>check.query("UPDATE api_reports SET projection='{}'::jsonb WHERE assessment_id=$1",[legacy]),/PHASE1_IMMUTABLE/);
   await check.query("ROLLBACK");
  }finally{check.release();}
  const r=await owner.query("SELECT version FROM api_schema_migrations ORDER BY version");
  assert.deepEqual(r.rows.map(x=>x.version),["001","002","003","004","005","006"]);
  const policies=await owner.query("SELECT c.relname AS tablename,c.relrowsecurity AS rowsecurity,c.relforcerowsecurity AS forcerowsecurity FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname LIKE 'api_auth_%' AND c.relkind='r'");
  assert.equal(policies.rowCount,4);
  assert.ok(policies.rows.every(x=>x.rowsecurity&&x.forcerowsecurity));
  const privileges=await owner.query("SELECT has_table_privilege('api_family','public.api_auth_evaluations','INSERT') AS can_insert,has_table_privilege('api_family_queue','public.api_auth_evaluations','INSERT') AS worker_insert");
  assert.equal(privileges.rows[0].can_insert,false);assert.equal(privileges.rows[0].worker_insert,true);
  const guard=await owner.query("SELECT has_table_privilege('api_family_queue','public.api_auth_profiles','UPDATE') AS can_update,has_function_privilege('api_family_queue','public.api_auth_fixture_lock_context(uuid,uuid,integer,uuid,integer,integer)','EXECUTE') AS can_guard");
  assert.equal(guard.rows[0].can_update,false);
  assert.equal(guard.rows[0].can_guard,true);
 }finally{
  if(service)await service.end();if(owner)await owner.end();
  try{await master.query("DROP DATABASE IF EXISTS "+db);}finally{await master.end();}
 }
});
