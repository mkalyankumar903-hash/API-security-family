import {test,after} from "node:test";
import assert from "node:assert/strict";
import {randomUUID} from "node:crypto";
import {Pool} from "pg";
import {migrate,withTenant,pool,closeDatabase} from "../packages/database/src/index.js";
const A="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const B="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
after(async()=>{await closeDatabase();});

test("Phase14 PostgreSQL16 concurrent migrators preserve exact historical 001-019 ledger",async()=>{
 await Promise.all([migrate(),migrate(),migrate()]);
 const r=await pool.query("SELECT version FROM api_schema_migrations ORDER BY version");
 assert.deepEqual(r.rows.map(x=>x.version),Array.from({length:19},(_,i)=>String(i+1).padStart(3,"0")));
});

test("Phase14 PostgreSQL RLS tenant context reset, transaction rollback and recovery",async()=>{
 const id=randomUUID();
 await assert.rejects(()=>withTenant(A,async tx=>{
  await tx.query("INSERT INTO api_audit(id,tenant_id,action,subject_id) VALUES($1,$2,'PHASE14_ROLLBACK',$3)",[id,A,id]);
  throw new Error("SYNTHETIC_ABORT");
 }),/SYNTHETIC_ABORT/);
 const check=await withTenant(A,tx=>tx.query("SELECT id FROM api_audit WHERE id=$1",[id]));
 assert.equal(check.rowCount,0);
 const ids=await Promise.all(Array.from({length:20},(_,i)=>withTenant(i%2===0?A:B,async tx=>{
  const result=await tx.query("SELECT current_setting('api.tenant_id',true) AS tenant");
  return result.rows[0].tenant as string;
 })));
 assert.deepEqual(ids.map((v,i)=>v=== (i%2===0?A:B)),Array(20).fill(true));
 const raw=await pool.connect();
 try{
  const q=await raw.query("SELECT nullif(current_setting('api.tenant_id',true),'') AS tenant");
  assert.equal(q.rows[0].tenant,null,"transaction-local identity must not leak into the pool");
 }finally{raw.release();}
});

test("Phase14 PostgreSQL bounded statement timeout leaves connection reusable",async()=>{
 await assert.rejects(()=>withTenant(A,async tx=>{
  await tx.query("SET LOCAL statement_timeout='40ms'");
  await tx.query("SELECT pg_sleep(0.5)");
 }),(e:unknown)=>typeof e==="object"&&e!==null&&"code" in e&&e.code==="57014");
 assert.equal(await withTenant(B,async tx=>{
  const r=await tx.query("SELECT current_setting('api.tenant_id',true) AS tenant");return r.rows[0].tenant;
 }),B);
});

test("Phase14 PostgreSQL connection acquisition saturates predictably and then recovers",async()=>{
 if(!process.env.DATABASE_URL)throw new Error("DATABASE_URL_REQUIRED");
 const short=new Pool({connectionString:process.env.DATABASE_URL,max:1,connectionTimeoutMillis:75});
 const held=await short.connect();
 try{
  await assert.rejects(()=>short.connect(),/timeout exceeded when trying to connect/);
 }finally{held.release();}
 const reclaimed=await short.connect();
 try{assert.equal((await reclaimed.query("SELECT 1 AS n")).rows[0].n,1);}finally{reclaimed.release();await short.end();}
});

test("Phase14 PostgreSQL creates a real deadlock, fails exactly one transaction and releases locks",async()=>{
 const first=await pool.connect(),second=await pool.connect();
 const k1=90314001,k2=90314002;
 try{
  await first.query("BEGIN");
  await second.query("BEGIN");
  await first.query("SELECT pg_advisory_xact_lock($1)",[k1]);
  await second.query("SELECT pg_advisory_xact_lock($1)",[k2]);
  const results=await Promise.allSettled([
   first.query("SELECT pg_advisory_xact_lock($1)",[k2]),
   second.query("SELECT pg_advisory_xact_lock($1)",[k1])
  ]);
  assert.equal(results.filter(x=>x.status==="rejected"&&
   typeof x.reason==="object"&&x.reason?.code==="40P01").length,1,
   "real PostgreSQL must abort one of the opposing advisory-lock transactions");
  assert.equal(results.filter(x=>x.status==="fulfilled").length,1);
 }finally{
  await Promise.allSettled([first.query("ROLLBACK"),second.query("ROLLBACK")]);
  first.release();second.release();
 }
 const recovered=await withTenant(A,tx=>tx.query("SELECT 1 AS ok"));
 assert.equal(recovered.rows[0].ok,1);
});

test("Phase14 PostgreSQL16 tenant-filtered read and transaction engineering benchmark",async()=>{
 const {performance}=await import("node:perf_hooks");
 const samples:number[]=[];
 for(let i=0;i<5;i++)await withTenant(A,tx=>tx.query("SELECT count(*)::int AS n FROM api_targets"));
 const baseline=process.memoryUsage().heapUsed;
 for(let i=0;i<30;i++){
  const start=performance.now();
  const r=await withTenant(i%2?A:B,tx=>tx.query(
   "SELECT count(*)::int AS n FROM api_targets WHERE tenant_id=current_setting('api.tenant_id',true)::uuid"));
  assert(Number.isInteger(r.rows[0].n));
  samples.push(performance.now()-start);
 }
 samples.sort((a,b)=>a-b);
 const report={workload:"tenant-scoped-transaction-and-index-filtered-read",
  iterations:samples.length,warmup:5,concurrency:1,tenantCount:2,
  medianMs:Number(samples[14]!.toFixed(3)),
  p95Ms:Number(samples[28]!.toFixed(3)),errors:0,
  heapDeltaBytes:process.memoryUsage().heapUsed-baseline,
  environment:"GitHub-hosted PostgreSQL16; engineering-only"};
 console.log("PHASE14_POSTGRES_ENGINEERING_BENCHMARK "+JSON.stringify(report));
});
