import {test} from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {Pool} from "pg";
test("upgrade real populated Phase 0 PostgreSQL 16 schema to Phase 1 forward-only without authorizing historical targets",async()=>{
 const adminUrl=process.env.MIGRATION_DATABASE_URL,appUrl=process.env.DATABASE_URL;
 assert.ok(adminUrl&&appUrl,"Actual PostgreSQL admin/app credentials required");
 const adminBase=new Pool({connectionString:adminUrl,max:1});
 const name="p1_upgrade_"+crypto.randomUUID().replaceAll("-","").slice(0,14);
 const appDB=new URL(appUrl);appDB.pathname="/"+name;
 const adminDB=new URL(adminUrl);adminDB.pathname="/"+name;
 let service:Pool|undefined,admin:Pool|undefined;
 const A="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",B="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
 const id=crypto.randomUUID();
 const base=(n:string)=>readFileSync(new URL("../packages/database/migrations/"+n,import.meta.url),"utf8");
 try{
  await adminBase.query("CREATE DATABASE "+name+" OWNER api_family");
  service=new Pool({connectionString:appDB.toString(),max:1});
  admin=new Pool({connectionString:adminDB.toString(),max:1});
  const session=await service.connect();
  try{
   await session.query("BEGIN");
   await session.query("SELECT set_config('api.tenant_id',$1,true)",[A]);
   await session.query(base("001_phase0.sql"));
   await session.query("CREATE TABLE api_schema_migrations(version text PRIMARY KEY)");
   await session.query("INSERT INTO api_schema_migrations(version) VALUES ('001')");
   await session.query("INSERT INTO api_targets(id,tenant_id,name,base_url,environment) VALUES($1,$2,'Phase0 Historical','https://legacy.fixture.invalid','SYNTHETIC')",[id,A]);
   const spec=crypto.randomUUID();
   await session.query("INSERT INTO api_specifications(id,tenant_id,target_id,filename,format,fingerprint,raw_spec) VALUES($1,$2,$3,'existing.json','OPENAPI_3_1',$4,'{}')",[spec,A,id,"a".repeat(64)]);
   await session.query("COMMIT");
  }catch(e){await session.query("ROLLBACK");throw e;}finally{session.release();}
  await admin.query("BEGIN");
  try{await admin.query(base("002_queue_isolation.sql"));await admin.query("INSERT INTO api_schema_migrations(version) VALUES ('002')");await admin.query("COMMIT");}
  catch(e){await admin.query("ROLLBACK");throw e;}
  await admin.query("BEGIN");
  try{await admin.query(base("003_phase1_target_onboarding.sql"));await admin.query("INSERT INTO api_schema_migrations(version) VALUES ('003')");await admin.query("COMMIT");}
  catch(e){await admin.query("ROLLBACK");throw e;}
  const app=await service.connect();
  try{
   await app.query("BEGIN");
   await app.query("SELECT set_config('api.tenant_id',$1,true)",[A]);
   const upgraded=await app.query("SELECT id,name,base_url,revision,scope_revision,ownership_status,lifecycle FROM api_targets WHERE id=$1",[id]);
   assert.equal(upgraded.rows[0].id,id);
   assert.equal(upgraded.rows[0].ownership_status,"PENDING_HOST_VERIFICATION");
   assert.equal(upgraded.rows[0].lifecycle,"ACTIVE");
   assert.equal(upgraded.rows[0].scope_revision,0);
   const specs=await app.query("SELECT id FROM api_specifications WHERE target_id=$1",[id]);
   assert.equal(specs.rowCount,1,"Phase 0 specifications must persist unchanged");
   const ledger=await app.query("SELECT version FROM api_schema_migrations ORDER BY version");
   assert.deepEqual(ledger.rows.map(x=>x.version),["001","002","003"]);
   await app.query("COMMIT");
   await app.query("BEGIN");
   await app.query("SELECT set_config('api.tenant_id',$1,true)",[B]);
   assert.equal((await app.query("SELECT id FROM api_targets WHERE id=$1",[id])).rowCount,0);
   await app.query("ROLLBACK");
  }finally{app.release();}
  await assert.rejects(()=>service!.query("INSERT INTO api_target_events(id,tenant_id,target_id,action,revision) VALUES($1,$2,$3,'FORGED',1)",[crypto.randomUUID(),A,id]),/row-level security/);
  // Re-applying the forward-only version is suppressed by the schema migration ledger.
  assert.equal((await admin.query("SELECT count(*)::int AS n FROM api_schema_migrations WHERE version='003'")).rows[0].n,1);
 }finally{
  if(service)await service.end();if(admin)await admin.end();
  try{await adminBase.query("DROP DATABASE IF EXISTS "+name);}finally{await adminBase.end();}
 }
});
