import { Pool, type PoolClient } from "pg";
import { readFileSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
export const pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 12, connectionTimeoutMillis: 5000, idleTimeoutMillis: 30000 });
export type Client = PoolClient;
export async function withTenant<T>(tenantId: string, fn: (tx: PoolClient) => Promise<T>): Promise<T> {
  if (!/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i.test(tenantId)) throw new Error("INVALID_TENANT_AUTHORITY");
  const tx = await pool.connect();
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
  const path = resolve(fileURLToPath(new URL("../migrations/001_phase0.sql", import.meta.url)));
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query(readFileSync(path,"utf8"));
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK"); throw error;
  } finally { client.release(); }
}
export async function claimJob(): Promise<{ assessment_id: string; tenant_id: string; claim_token: string } | null> {
  const claimToken = uuid();
  const r = await pool.query(
    "WITH available AS (SELECT assessment_id FROM api_assessment_queue WHERE locked_until IS NULL OR locked_until < now() ORDER BY assessment_id LIMIT 1 FOR UPDATE SKIP LOCKED) UPDATE api_assessment_queue q SET claim_token = $1, locked_until = now() + interval '60 seconds' FROM available a WHERE q.assessment_id = a.assessment_id RETURNING q.assessment_id,q.tenant_id,q.claim_token", [claimToken]);
  return r.rows[0] ?? null;
}
export async function closeDatabase(): Promise<void> { await pool.end(); }
