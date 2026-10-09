import {test} from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {Pool} from "pg";
const A="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const migration=(file:string)=>readFileSync(new URL("../packages/database/migrations/"+file,import.meta.url),"utf8");
test("populated Phase02 database upgrades to 005 retaining report bytes and historical legacy authority",async()=>{
 const name="phase03_upgrade_"+crypto.randomUUID().replaceAll("-","").slice(0,12);
 const adminUrl=process.env.MIGRATION_DATABASE_URL!,appUrl=process.env.DATABASE_URL!;
 const admin=new URL(adminUrl),app=new URL(appUrl),master=new Pool({connectionString:adminUrl});
 admin.pathname="/"+name;app.pathname="/"+name;
 let owner:Pool|undefined,service:Pool|undefined;
 const target=crypto.randomUUID(),spec=crypto.randomUUID(),assessment=crypto.randomUUID(),report=crypto.randomUUID();
 try{
  await master.query("CREATE DATABASE "+name+" OWNER api_family");
  owner=new Pool({connectionString:admin.toString()});service=new Pool({connectionString:app.toString()});
  {
  const tx=await service.connect();
  try{
   await tx.query("BEGIN");await tx.query("SELECT set_config('api.tenant_id',$1,true)",[A]);
   await tx.query(migration("001_phase0.sql"));
   await tx.query("CREATE TABLE api_schema_migrations(version text PRIMARY KEY)");
   await tx.query("INSERT INTO api_schema_migrations VALUES('001')");
   await tx.query("INSERT INTO api_targets(id,tenant_id,name,base_url,environment) VALUES($1,$2,'Upgrade','https://upgrade.fixture.invalid','SYNTHETIC')",[target,A]);
   await tx.query("INSERT INTO api_specifications(id,tenant_id,target_id,filename,format,fingerprint,raw_spec) VALUES($1,$2,$3,'old.json','OPENAPI_3_1',$4,$5)",[spec,A,target,"a".repeat(64),'{"openapi":"3.1.0","paths":{}}']);
   await tx.query("INSERT INTO api_assessments(id,tenant_id,target_id,specification_id,status,mode,idempotency_key) VALUES($1,$2,$3,$4,'COMPLETED','SPEC_ONLY','legacy-005')",[assessment,A,target,spec]);
   await tx.query("INSERT INTO api_reports(id,tenant_id,assessment_id,projection) VALUES($1,$2,$3,$4::jsonb)",[report,A,assessment,JSON.stringify({source:"Phase02",snapshot:true})]);
   await tx.query("COMMIT");
  }catch(e){await tx.query("ROLLBACK");throw e;}finally{tx.release();}
  }
  for(const [v,f] of [["002","002_queue_isolation.sql"],["003","003_phase1_target_onboarding.sql"],["004","004_phase2_offline_discovery.sql"],["005","005_phase3_deterministic_detection.sql"]] as const){
   await owner.query("BEGIN");try{await owner.query(migration(f));await owner.query("INSERT INTO api_schema_migrations(version) VALUES($1)",[v]);await owner.query("COMMIT");}
   catch(e){await owner.query("ROLLBACK");throw e;}
  }
  const tx=await service.connect();
  try{
   await tx.query("BEGIN");await tx.query("SELECT set_config('api.tenant_id',$1,true)",[A]);
   const row=(await tx.query("SELECT engine_version,inventory_fingerprint FROM api_assessments WHERE id=$1",[assessment])).rows[0];
   assert.equal(row.engine_version,"legacy-v1");assert.equal(row.inventory_fingerprint,null);
   assert.deepEqual((await tx.query("SELECT projection FROM api_reports WHERE id=$1",[report])).rows[0].projection,{source:"Phase02",snapshot:true});
   await assert.rejects(()=>tx.query("UPDATE api_reports SET projection='{}'::jsonb WHERE id=$1",[report]),/PHASE1_IMMUTABLE/);
   await tx.query("ROLLBACK");
  }finally{tx.release();}
  assert.equal((await service.query("SELECT count(*)::int AS n FROM api_assessments")).rows[0].n,0);
  assert.deepEqual((await owner.query("SELECT version FROM api_schema_migrations ORDER BY version")).rows.map(x=>x.version),["001","002","003","004","005"]);
 }finally{
  if(service)await service.end();if(owner)await owner.end();
  try{await master.query("DROP DATABASE IF EXISTS "+name);}finally{await master.end();}
 }
});
