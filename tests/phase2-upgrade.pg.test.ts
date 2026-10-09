import {test} from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {Pool} from "pg";
const A="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const migration=(file:string)=>readFileSync(new URL("../packages/database/migrations/"+file,import.meta.url),"utf8");
test("populated genuine Phase 1 PG schema upgrades forward-only to 004, retaining old spec and report identity",async()=>{
 const adminUrl=process.env.MIGRATION_DATABASE_URL,appUrl=process.env.DATABASE_URL;
 assert.ok(adminUrl&&appUrl);
 const name="phase02_upgrade_"+crypto.randomUUID().replaceAll("-","").slice(0,12);
 const master=new Pool({connectionString:adminUrl,max:1}),asAdmin=new URL(adminUrl),asService=new URL(appUrl);
 asAdmin.pathname="/"+name;asService.pathname="/"+name;
 let owner:Pool|undefined,client:Pool|undefined;
 const targetId=crypto.randomUUID(),oldSpec=crypto.randomUUID(),oldAssessment=crypto.randomUUID(),oldReport=crypto.randomUUID();
 try{
  await master.query("CREATE DATABASE "+name+" OWNER api_family");
  owner=new Pool({connectionString:asAdmin.toString(),max:1});
  client=new Pool({connectionString:asService.toString(),max:1});
  const session=await client.connect();
  try{
   await session.query("BEGIN");await session.query("SELECT set_config('api.tenant_id',$1,true)",[A]);
   await session.query(migration("001_phase0.sql"));
   await session.query("CREATE TABLE api_schema_migrations(version text PRIMARY KEY)");
   await session.query("INSERT INTO api_schema_migrations VALUES('001')");
   await session.query("INSERT INTO api_targets(id,tenant_id,name,base_url,environment) VALUES($1,$2,'Legacy Target','https://legacy.fixture.invalid','SYNTHETIC')",[targetId,A]);
   await session.query("INSERT INTO api_specifications(id,tenant_id,target_id,filename,format,fingerprint,raw_spec) VALUES($1,$2,$3,'legacy.json','OPENAPI_3_1',$4,$5)",
    [oldSpec,A,targetId,"a".repeat(64),'{"openapi":"3.1.0","info":{"title":"Legacy","version":"1.0.0"},"paths":{}}']);
   await session.query("INSERT INTO api_assessments(id,tenant_id,target_id,specification_id,status,mode,idempotency_key) VALUES($1,$2,$3,$4,'COMPLETED','SPEC_ONLY','legacy-b1')",
    [oldAssessment,A,targetId,oldSpec]);
   await session.query("INSERT INTO api_reports(id,tenant_id,assessment_id,projection) VALUES($1,$2,$3,$4::jsonb)",
    [oldReport,A,oldAssessment,JSON.stringify({phase:0,unchanged:true,provenance:oldSpec})]);
   await session.query("COMMIT");
  }catch(e){await session.query("ROLLBACK");throw e;}finally{session.release();}
  for(const [version,file] of [["002","002_queue_isolation.sql"],["003","003_phase1_target_onboarding.sql"],["004","004_phase2_offline_discovery.sql"]] as const){
   await owner.query("BEGIN");
   try{await owner.query(migration(file));await owner.query("INSERT INTO api_schema_migrations(version) VALUES($1)",[version]);await owner.query("COMMIT");}
   catch(e){await owner.query("ROLLBACK");throw e;}
  }
  const tx=await client.connect();
  try{
   await tx.query("BEGIN");await tx.query("SELECT set_config('api.tenant_id',$1,true)",[A]);
   const legacy=await tx.query("SELECT id,ownership_status,lifecycle FROM api_targets WHERE id=$1",[targetId]);
   assert.equal(legacy.rows[0].ownership_status,"PENDING_HOST_VERIFICATION");assert.equal(legacy.rows[0].lifecycle,"ACTIVE");
   assert.equal((await tx.query("SELECT id FROM api_specifications WHERE id=$1",[oldSpec])).rowCount,1);
   assert.equal((await tx.query("SELECT id FROM api_assessments WHERE id=$1",[oldAssessment])).rowCount,1);
   const report=(await tx.query("SELECT projection FROM api_reports WHERE id=$1",[oldReport])).rows[0].projection;
   assert.deepEqual(report,{phase:0,unchanged:true,provenance:oldSpec});
   assert.equal((await tx.query("SELECT specification_id FROM api_spec_inventories WHERE target_id=$1",[targetId])).rowCount,0);
   assert.deepEqual((await tx.query("SELECT version FROM api_schema_migrations ORDER BY version")).rows.map(r=>r.version),["001","002","003","004"]);
   await tx.query("COMMIT");
  }finally{tx.release();}
  const unscoped=await client.query("SELECT * FROM api_spec_imports");
  assert.equal(unscoped.rowCount,0);
  await assert.rejects(()=>client!.query("INSERT INTO api_spec_imports(id,tenant_id,target_id,idempotency_key,fingerprint,status) VALUES($1,$2,$3,'forged-attempt1',$4,'RECEIVED')",
   [crypto.randomUUID(),A,targetId,"a".repeat(64)]),/row-level security/);
 }finally{
  if(client)await client.end();if(owner)await owner.end();
  try{await master.query("DROP DATABASE IF EXISTS "+name);}finally{await master.end();}
 }
});
