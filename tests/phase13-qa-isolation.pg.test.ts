/** Actual PostgreSQL 16 independent app/worker/QA role privilege negative tests. */
import {test} from "node:test";
import assert from "node:assert/strict";
import {migrate,withQaTenant,pool,workerPool,closeDatabase} from "../packages/database/src/index.js";
const A="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const B="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const qaTables=["api_v13_qa_delivery","api_v13_qa_delivery_events","api_v13_qa_sink_receipts"] as const;
const denied=(e:unknown)=>(e as {code?:string}).code==="42501";
test("Phase13 migration 019: independent SQL identity and real privilege isolation",async t=>{
 if(process.env.NODE_ENV!=="test"||!process.env.PHASE13_QA_DB_PASSWORD)throw Error("TEST_ONLY_QA_ROLE_REQUIRED");
 await migrate();
 try{
  assert.equal((await pool.query("SELECT count(*)::int AS n FROM public.api_schema_migrations")).rows[0].n,19);
  for(const tab of ["api_v13_feature_sources",...qaTables]){
   const q=await pool.query("SELECT relrowsecurity,relforcerowsecurity FROM pg_class WHERE oid=$1::regclass",["public."+tab]);
   assert.equal(q.rows[0].relrowsecurity,true,tab+" tenant RLS");
   assert.equal(q.rows[0].relforcerowsecurity,true,tab+" FORCE RLS");
  }
  await t.test("ordinary application and worker roles cannot SELECT/INSERT/UPDATE/DELETE any QA table",async()=>{
   for(const [role,p] of [["api_family",pool],["api_family_queue",workerPool]] as const){
    for(const tab of qaTables){
     const name="public."+tab;
     const grants=await p.query("SELECT current_user AS role,has_table_privilege(current_user,$1,'SELECT') AS s,has_table_privilege(current_user,$1,'INSERT') AS i,has_table_privilege(current_user,$1,'DELETE') AS d",[name]);
     assert.equal(grants.rows[0].role,role);
     for(const k of ["s","i","d"])assert.equal(grants.rows[0][k],false,role+":"+tab+":"+k);
     await assert.rejects(()=>p.query("SELECT * FROM "+name+" LIMIT 1"),denied);
     await assert.rejects(()=>p.query("INSERT INTO "+name+" DEFAULT VALUES"),denied);
     await assert.rejects(()=>p.query("UPDATE "+name+" SET id=id WHERE false"),denied);
     await assert.rejects(()=>p.query("DELETE FROM "+name+" WHERE false"),denied);
    }
   }
  });
  await t.test("QA principal has only authorized table rights and sees no other tenant",async()=>{
   const result=await withQaTenant(A,async tx=>{
    const grants=await tx.query("SELECT current_user AS role,has_table_privilege(current_user,'public.api_v13_outbox','SELECT') AS r,has_table_privilege(current_user,'public.api_v13_outbox','UPDATE') AS u,has_table_privilege(current_user,'public.api_v13_outbox','INSERT') AS i,has_table_privilege(current_user,'public.api_v13_feature_sources','SELECT') AS f,has_schema_privilege(current_user,'public','CREATE') AS c");
    const count=await tx.query("SELECT count(*)::int AS n FROM public.api_v13_qa_delivery");
    return {grants:grants.rows[0],count:count.rows[0].n as number};
   });
   assert.equal(result.grants.role,"api_family_qa_ci");
   assert.equal(result.grants.r,true);
   for(const k of ["u","i","f","c"])assert.equal(result.grants[k],false,k);
   assert(result.count>=1,"previous same-DB Phase13 PostgreSQL fixture must have inserted QA rows");
   assert.equal((await withQaTenant(B,tx=>tx.query("SELECT count(*)::int AS n FROM public.api_v13_qa_delivery"))).rows[0].n,0);
   await assert.rejects(()=>withQaTenant(A,tx=>tx.query("UPDATE public.api_v13_outbox SET attempt_count=1 WHERE false")),denied);
   await assert.rejects(()=>withQaTenant(A,tx=>tx.query("SELECT * FROM public.api_v13_feature_sources")),denied);
   await assert.rejects(()=>withQaTenant(A,tx=>tx.query("DELETE FROM public.api_v13_qa_delivery WHERE false")),denied);
   await assert.rejects(()=>withQaTenant(A,tx=>tx.query("UPDATE public.api_v13_qa_sink_receipts SET id=id WHERE false")),denied);
  });
  await t.test("real outbox remains DISABLED and zero-attempt after QA lifecycle",async()=>{
   const q=await pool.query("SELECT count(*)::int AS total,count(*) FILTER(WHERE delivery_state='DISABLED' AND attempt_count=0 AND delivered_at IS NULL AND last_attempt_at IS NULL)::int AS safe FROM public.api_v13_outbox");
   assert(q.rows[0].total>=2);
   assert.equal(q.rows[0].total,q.rows[0].safe);
  });
 }finally{await closeDatabase();}
});
