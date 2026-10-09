import { Pool, type PoolClient } from "pg";
import { readFileSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
export const pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 12, connectionTimeoutMillis: 5000, idleTimeoutMillis: 30000 });
// The worker role is a separate database principal. The tenant-facing role cannot
// SELECT/UPDATE/DELETE/CLAIM queue records; never share these connection strings.
export const workerPool = new Pool({ connectionString: process.env.WORKER_DATABASE_URL, max: 5, connectionTimeoutMillis: 5000, idleTimeoutMillis: 30000 });
export type Client = PoolClient;
export function withTenant<T>(tenantId: string, fn: (tx: PoolClient) => Promise<T>): Promise<T> {
  return tenantTransaction(pool,tenantId,fn);
}
export function withWorkerTenant<T>(tenantId: string,fn:(tx:PoolClient)=>Promise<T>):Promise<T> {
  if (!process.env.WORKER_DATABASE_URL) throw new Error("WORKER_DATABASE_URL_REQUIRED");
  return tenantTransaction(workerPool,tenantId,fn);
}
async function tenantTransaction<T>(connection:Pool,tenantId:string,fn:(tx:PoolClient)=>Promise<T>):Promise<T> {
  if (!/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i.test(tenantId)) throw new Error("INVALID_TENANT_AUTHORITY");
  const tx = await connection.connect();
  try {
    await tx.query("BEGIN");
    await tx.query("SELECT set_config('api.tenant_id', $1, true)", [tenantId]);
    const result = await fn(tx);
    await tx.query("COMMIT");
    return result;
  } catch (error) {
    await tx.query("ROLLBACK");
    throw error;
  } finally { tx.release(); }
}
export const uuid = () => randomUUID();
export async function migrate(): Promise<void> {
  if (!process.env.MIGRATION_DATABASE_URL) throw new Error("MIGRATION_DATABASE_URL_REQUIRED");
  const baseline = resolve(fileURLToPath(new URL("../migrations/001_phase0.sql", import.meta.url)));
  const isolation = resolve(fileURLToPath(new URL("../migrations/002_queue_isolation.sql", import.meta.url)));
  const onboarding = resolve(fileURLToPath(new URL("../migrations/003_phase1_target_onboarding.sql", import.meta.url)));
  const discovery = resolve(fileURLToPath(new URL("../migrations/004_phase2_offline_discovery.sql", import.meta.url)));
  const phase3 = resolve(fileURLToPath(new URL("../migrations/005_phase3_deterministic_detection.sql", import.meta.url)));
  const phase4 = resolve(fileURLToPath(new URL("../migrations/006_phase4_authenticated_fixture.sql", import.meta.url)));
  const phase5 = resolve(fileURLToPath(new URL("../migrations/007_phase5_unified_assessment.sql", import.meta.url)));
  const rich5 = resolve(fileURLToPath(new URL("../migrations/008_phase5_rich_offline.sql", import.meta.url)));
  const pt6 = resolve(fileURLToPath(new URL("../migrations/009_phase6_pt_safe_execution.sql", import.meta.url)));
  const pt6h = resolve(fileURLToPath(new URL("../migrations/010_phase6_permit_storage_hardening.sql", import.meta.url)));
  const pt7 = resolve(fileURLToPath(new URL("../migrations/011_phase7_pt_detection.sql", import.meta.url)));
  const pt8 = resolve(fileURLToPath(new URL("../migrations/012_phase8_complete_pt_product.sql", import.meta.url)));
  const pt9 = resolve(fileURLToPath(new URL("../migrations/013_phase9_deterministic_orchestrator.sql", import.meta.url)));
  const pt10 = resolve(fileURLToPath(new URL("../migrations/014_phase10_worker_execution_safety.sql", import.meta.url)));
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("CREATE TABLE IF NOT EXISTS api_schema_migrations(version text PRIMARY KEY)");
    const already = await client.query("SELECT version FROM api_schema_migrations WHERE version='001'");
    if (!already.rowCount) {
      await client.query(readFileSync(baseline,"utf8"));
      await client.query("INSERT INTO api_schema_migrations(version) VALUES('001')");
    }
    await client.query("COMMIT");
  } catch(error) { await client.query("ROLLBACK"); throw error; }
  finally { client.release(); }
  const privileged = new Pool({connectionString:process.env.MIGRATION_DATABASE_URL,max:1});
  const owner=await privileged.connect();
  try {
    await owner.query("BEGIN");
    const already=await owner.query("SELECT version FROM api_schema_migrations WHERE version='002'");
    if (!already.rowCount) {
      await owner.query(readFileSync(isolation,"utf8"));
      await owner.query("INSERT INTO api_schema_migrations(version) VALUES('002')");
    }
    const phase1=await owner.query("SELECT version FROM api_schema_migrations WHERE version='003'");
    if(!phase1.rowCount){
      await owner.query(readFileSync(onboarding,"utf8"));
      await owner.query("INSERT INTO api_schema_migrations(version) VALUES('003')");
    }
    const phase2=await owner.query("SELECT version FROM api_schema_migrations WHERE version='004'");
    if(!phase2.rowCount){
      await owner.query(readFileSync(discovery,"utf8"));
      await owner.query("INSERT INTO api_schema_migrations(version) VALUES('004')");
    }
    const p3=await owner.query("SELECT version FROM api_schema_migrations WHERE version='005'");
    if(!p3.rowCount){
      await owner.query(readFileSync(phase3,"utf8"));
      await owner.query("INSERT INTO api_schema_migrations(version) VALUES('005')");
    }
    const p4=await owner.query("SELECT version FROM api_schema_migrations WHERE version='006'");
    if(!p4.rowCount){
      await owner.query(readFileSync(phase4,"utf8"));
      await owner.query("INSERT INTO api_schema_migrations(version) VALUES('006')");
    }
    const p5=await owner.query("SELECT version FROM api_schema_migrations WHERE version='007'");
    if(!p5.rowCount){
      await owner.query(readFileSync(phase5,"utf8"));
      await owner.query("INSERT INTO api_schema_migrations(version) VALUES('007')");
    }
    const p8=await owner.query("SELECT version FROM api_schema_migrations WHERE version='008'");
    if(!p8.rowCount){
      await owner.query(readFileSync(rich5,"utf8"));
      await owner.query("INSERT INTO api_schema_migrations(version) VALUES('008')");
    }
    const p9=await owner.query("SELECT version FROM api_schema_migrations WHERE version='009'");
    if(!p9.rowCount){
      await owner.query(readFileSync(pt6,"utf8"));
      await owner.query("INSERT INTO api_schema_migrations(version) VALUES('009')");
    }
    const hardened=await owner.query("SELECT version FROM api_schema_migrations WHERE version='010'");
    if(!hardened.rowCount){
      await owner.query(readFileSync(pt6h,"utf8"));
      await owner.query("INSERT INTO api_schema_migrations(version) VALUES('010')");
    }
    const detect7=await owner.query("SELECT version FROM api_schema_migrations WHERE version='011'");
    if(!detect7.rowCount){
      await owner.query(readFileSync(pt7,"utf8"));
      await owner.query("INSERT INTO api_schema_migrations(version) VALUES('011')");
    }
    const phase08=await owner.query("SELECT version FROM api_schema_migrations WHERE version='012'");
    if(!phase08.rowCount){
      await owner.query(readFileSync(pt8,"utf8"));
      await owner.query("INSERT INTO api_schema_migrations(version) VALUES('012')");
    }
    const phase09=await owner.query("SELECT version FROM api_schema_migrations WHERE version='013'");
    if(!phase09.rowCount){
      await owner.query(readFileSync(pt9,"utf8"));
      await owner.query("INSERT INTO api_schema_migrations(version) VALUES('013')");
    }
    const phase10=await owner.query("SELECT version FROM api_schema_migrations WHERE version='014'");
    if(!phase10.rowCount){
      await owner.query(readFileSync(pt10,"utf8"));
      await owner.query("INSERT INTO api_schema_migrations(version) VALUES('014')");
    }
    await owner.query("COMMIT");
  } catch(error) {await owner.query("ROLLBACK"); throw error;}
  finally {owner.release();await privileged.end();}
}
/** pt-worker-safety-v1: a claim is a temporary fenced processing lease, NEVER a permit.
 * A private SKIP LOCKED gate serializes capacity checks across independent workers.
 * Database clock governs expiry, not the caller clock. */
export type WorkerClaim={assessment_id:string;tenant_id:string;claim_token:string;claim_generation:number;attempt_id:string};
export async function claimJob():Promise<WorkerClaim|null>{
 if(!process.env.WORKER_DATABASE_URL)throw new Error("WORKER_DATABASE_URL_REQUIRED");
 const tx=await workerPool.connect();
 try{
  await tx.query("BEGIN");
  // Capacity check must serialize, but not drop other eligible jobs if this
  // short-lived gate is busy: bounded wait, SKIP LOCKED retained per job row.
  await tx.query("SET LOCAL lock_timeout='1500ms'");
  const gate=await tx.query("SELECT id FROM api_queue.api_worker_claim_gate WHERE id=true FOR UPDATE");
  if(!gate.rowCount){await tx.query("COMMIT");return null;}
  const picked=await tx.query(
   `SELECT q.assessment_id,q.tenant_id,q.claim_generation FROM api_queue.api_assessment_queue q
     LEFT JOIN api_queue.api_worker_tenant_schedule s ON s.tenant_id=q.tenant_id
     WHERE (q.locked_until IS NULL OR q.locked_until < clock_timestamp())
       AND (q.next_eligible_at IS NULL OR q.next_eligible_at <= clock_timestamp())
       AND (SELECT count(*) FROM api_queue.api_assessment_queue active
         WHERE active.tenant_id=q.tenant_id AND active.locked_until>clock_timestamp()) < 2
     ORDER BY COALESCE(s.last_claimed_at,'epoch'::timestamptz),q.created_at,q.assessment_id
     LIMIT 1 FOR UPDATE OF q SKIP LOCKED`);
  if(!picked.rowCount){await tx.query("COMMIT");return null;}
  const q=picked.rows[0] as {assessment_id:string;tenant_id:string;claim_generation:string};
  await tx.query("SELECT set_config('api.tenant_id',$1,true)",[q.tenant_id]);
  const current=await tx.query("SELECT status FROM public.api_assessments WHERE id=$1 FOR UPDATE",[q.assessment_id]);
  if(!current.rowCount||["COMPLETED","CANCELLED","FAILED"].includes(current.rows[0].status)){
   await tx.query("DELETE FROM api_queue.api_assessment_queue WHERE assessment_id=$1",[q.assessment_id]);
   await tx.query("COMMIT");return null;
  }
  const token=uuid(),attempt=uuid();
  const claimed=await tx.query(
   "UPDATE api_queue.api_assessment_queue SET claim_token=$2,claim_generation=claim_generation+1,claimed_at=clock_timestamp(),last_heartbeat_at=clock_timestamp(),locked_until=clock_timestamp()+interval '45 seconds' WHERE assessment_id=$1 RETURNING claim_generation",
   [q.assessment_id,token]);
  await tx.query("UPDATE public.api_assessments SET status='PROCESSING' WHERE id=$1 AND status='QUEUED'",[q.assessment_id]);
  await tx.query("UPDATE public.api_worker_attempts SET state='LOST',finished_at=clock_timestamp(),failure_code='LEASE_REPLACED' WHERE assessment_id=$1 AND state='ACTIVE'",[q.assessment_id]);
  await tx.query("INSERT INTO public.api_worker_attempts(id,tenant_id,assessment_id,claim_generation,claim_token,state) VALUES($1,$2,$3,$4,$5,'ACTIVE')",
   [attempt,q.tenant_id,q.assessment_id,claimed.rows[0].claim_generation,token]);
  await tx.query("INSERT INTO public.api_worker_events(id,tenant_id,assessment_id,attempt_id,kind,code) VALUES($1,$2,$3,$4,$5,$6)",
   [uuid(),q.tenant_id,q.assessment_id,attempt,Number(q.claim_generation)>0?"TAKEOVER":"CLAIMED","LEASE_OWNED"]);
  await tx.query("INSERT INTO api_queue.api_worker_tenant_schedule(tenant_id,last_claimed_at) VALUES($1,clock_timestamp()) ON CONFLICT(tenant_id) DO UPDATE SET last_claimed_at=EXCLUDED.last_claimed_at",[q.tenant_id]);
  await tx.query("COMMIT");
  return {assessment_id:q.assessment_id,tenant_id:q.tenant_id,claim_token:token,
   claim_generation:Number(claimed.rows[0].claim_generation),attempt_id:attempt};
 }catch(e){await tx.query("ROLLBACK");throw e;}finally{tx.release();}
}

/** Renewal follows accepted stop -> permit/target -> queue lock order.
 * Success means only processing ownership; the governor remains sole execution authority. */
export async function renewWorkerClaim(claim:WorkerClaim):Promise<boolean>{
 return withWorkerTenant(claim.tenant_id,async tx=>{
  const stop=await tx.query("SELECT enabled FROM public.api_pt_stop WHERE tenant_id=$1 FOR UPDATE",[claim.tenant_id]);
  if(stop.rows[0]?.enabled===true)return false;
  const pt=await tx.query(
   `SELECT j.job_deadline,p.expires_at,p.revoked_at,t.lifecycle,t.environment,
    (t.verification_version=s.target_verification_version AND t.scope_revision=s.target_scope_revision) AS same_scope
    FROM public.api_pt_jobs j
    JOIN public.api_pt_permits p ON p.id=j.permit_id AND p.tenant_id=j.tenant_id
    JOIN public.api_pt_scopes s ON s.id=j.scope_id AND s.tenant_id=j.tenant_id
    JOIN public.api_targets t ON t.id=j.target_id AND t.tenant_id=j.tenant_id
    WHERE j.assessment_id=$1 FOR UPDATE OF j,p,t`,[claim.assessment_id]);
  if(pt.rowCount){
   const p=pt.rows[0];
   if(p.revoked_at||p.lifecycle!=="ACTIVE"||p.environment!=="SYNTHETIC"||!p.same_scope)return false;
  }
  const q=await tx.query("SELECT claim_token,claim_generation,locked_until FROM api_queue.api_assessment_queue WHERE assessment_id=$1 FOR UPDATE",[claim.assessment_id]);
  if(q.rows[0]?.claim_token!==claim.claim_token||Number(q.rows[0]?.claim_generation)!==claim.claim_generation)return false;
  const status=await tx.query("SELECT status FROM public.api_assessments WHERE id=$1 FOR UPDATE",[claim.assessment_id]);
  if(status.rows[0]?.status!=="PROCESSING")return false;
  const cap=pt.rowCount?[pt.rows[0].job_deadline,pt.rows[0].expires_at]:[null,null];
  const renewed=await tx.query(
   `UPDATE api_queue.api_assessment_queue SET
     locked_until=LEAST(clock_timestamp()+interval '45 seconds',
      COALESCE($4::timestamptz,'infinity'::timestamptz),
      COALESCE($5::timestamptz,'infinity'::timestamptz)),
     last_heartbeat_at=clock_timestamp()
     WHERE assessment_id=$1 AND claim_token=$2 AND claim_generation=$3
      AND locked_until>clock_timestamp()
      AND LEAST(COALESCE($4::timestamptz,'infinity'::timestamptz),
       COALESCE($5::timestamptz,'infinity'::timestamptz))>clock_timestamp()
     RETURNING claim_generation`,
   [claim.assessment_id,claim.claim_token,claim.claim_generation,...cap]);
  if(!renewed.rowCount)return false;
  await tx.query("UPDATE public.api_worker_attempts SET last_heartbeat_at=clock_timestamp() WHERE id=$1 AND claim_token=$2 AND state='ACTIVE'",
   [claim.attempt_id,claim.claim_token]);
  return true;
 });
}

/** Only call immediately after a claim and BEFORE beginning processing. Once a
 * fixture/stage may have executed, do NOT use this function to release ownership. */
export async function releaseUnstartedWorkerClaim(claim:WorkerClaim):Promise<boolean>{
 return withWorkerTenant(claim.tenant_id,async tx=>{
  const q=await tx.query(
   "SELECT claim_token,claim_generation,locked_until FROM api_queue.api_assessment_queue WHERE assessment_id=$1 FOR UPDATE",
   [claim.assessment_id]);
  if(q.rows[0]?.claim_token!==claim.claim_token||
   Number(q.rows[0]?.claim_generation)!==claim.claim_generation)return false;
  const out=await tx.query(
   "UPDATE api_queue.api_assessment_queue SET claim_token=NULL,locked_until=NULL,claimed_at=NULL,last_heartbeat_at=NULL WHERE assessment_id=$1 AND claim_token=$2 AND claim_generation=$3",
   [claim.assessment_id,claim.claim_token,claim.claim_generation]);
  await tx.query(
   "UPDATE api_worker_attempts SET state='LOST',finished_at=clock_timestamp(),failure_code='SHUTDOWN_BEFORE_EXECUTION' WHERE id=$1 AND state='ACTIVE'",
   [claim.attempt_id]);
  await tx.query(
   "INSERT INTO api_worker_events(id,tenant_id,assessment_id,attempt_id,kind,code) VALUES($1,$2,$3,$4,'LEASE_LOST','SHUTDOWN_BEFORE_EXECUTION')",
   [uuid(),claim.tenant_id,claim.assessment_id,claim.attempt_id]);
  return Boolean(out.rowCount);
 });
}

/** Final state comes from committed PostgreSQL status, never a worker's success flag. */
export async function finishWorkerAttempt(claim:WorkerClaim):Promise<void>{
 await withWorkerTenant(claim.tenant_id,async tx=>{
  const state=await tx.query("SELECT status FROM public.api_assessments WHERE id=$1",[claim.assessment_id]);
  const q=await tx.query("SELECT claim_token,claim_generation FROM api_queue.api_assessment_queue WHERE assessment_id=$1",[claim.assessment_id]);
  const current=!q.rowCount||(q.rows[0].claim_token===claim.claim_token&&Number(q.rows[0].claim_generation)===claim.claim_generation);
  const s=state.rows[0]?.status;
  const outcome=current&&s==="COMPLETED"?"COMPLETED":current&&s==="CANCELLED"?"CANCELLED":current&&s==="FAILED"?"FAILED":"LOST";
  const changed=await tx.query("UPDATE public.api_worker_attempts SET state=$2,finished_at=clock_timestamp(),failure_code=CASE WHEN $2='LOST' THEN 'AUTHORITY_OR_TERMINAL_NOT_CONFIRMED' ELSE NULL END WHERE id=$1 AND claim_token=$3 AND state='ACTIVE' RETURNING id",
   [claim.attempt_id,outcome,claim.claim_token]);
  if(changed.rowCount)await tx.query("INSERT INTO public.api_worker_events(id,tenant_id,assessment_id,attempt_id,kind,code) VALUES($1,$2,$3,$4,$5,$6)",
   [uuid(),claim.tenant_id,claim.assessment_id,claim.attempt_id,outcome==="LOST"?"LEASE_LOST":outcome,outcome==="LOST"?"AUTHORITY_NOT_CONFIRMED":"PERSISTED_ASSESSMENT_STATE"]);
 });
}
export async function closeDatabase(): Promise<void> { await pool.end(); await workerPool.end(); }
