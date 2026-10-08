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
    await owner.query("COMMIT");
  } catch(error) {await owner.query("ROLLBACK"); throw error;}
  finally {owner.release();await privileged.end();}
}
export async function claimJob(): Promise<{ assessment_id: string; tenant_id: string; claim_token: string } | null> {
  const claimToken = uuid();
  if (!process.env.WORKER_DATABASE_URL) throw new Error("WORKER_DATABASE_URL_REQUIRED");
  const r = await workerPool.query(
    "WITH available AS (SELECT assessment_id FROM api_queue.api_assessment_queue WHERE locked_until IS NULL OR locked_until < now() ORDER BY assessment_id LIMIT 1 FOR UPDATE SKIP LOCKED) UPDATE api_queue.api_assessment_queue q SET claim_token = $1, locked_until = now() + interval '60 seconds' FROM available a WHERE q.assessment_id = a.assessment_id RETURNING q.assessment_id,q.tenant_id,q.claim_token", [claimToken]);
  return r.rows[0] ?? null;
}
export async function closeDatabase(): Promise<void> { await pool.end(); await workerPool.end(); }
