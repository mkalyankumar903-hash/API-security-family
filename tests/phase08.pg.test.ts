import {test} from "node:test";
import assert from "node:assert/strict";
import {migrate,pool,withTenant,closeDatabase} from "../packages/database/src/index.js";
test("Phase08 PostgreSQL 16 terminal coverage FORCE RLS and additive migration",async()=>{
 try{
  await migrate();
  const q=await pool.query("SELECT version FROM api_schema_migrations WHERE version='012'");
  assert.equal(q.rowCount,1);
  const t=await pool.query("SELECT relrowsecurity,relforcerowsecurity FROM pg_class WHERE relname='api_pt8_terminal_coverage'");
  assert.equal(t.rowCount,1);
  assert.equal(t.rows[0].relrowsecurity,true);
  assert.equal(t.rows[0].relforcerowsecurity,true);
  assert.equal((await pool.query("SELECT count(*)::int AS n FROM api_pt8_terminal_coverage")).rows[0].n,0);
  const tenant="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
  assert.equal((await withTenant(tenant,tx=>tx.query("SELECT count(*)::int AS n FROM api_pt8_terminal_coverage"))).rows[0].n,0);
  await assert.rejects(()=>withTenant(tenant,tx=>tx.query(
   "UPDATE api_pt8_terminal_coverage SET projection='{}'::jsonb WHERE tenant_id=$1",[tenant])),/permission denied|immutable/i);
 }finally{await closeDatabase();}
});
