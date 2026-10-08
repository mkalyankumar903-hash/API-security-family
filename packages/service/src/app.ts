import Fastify, { type FastifyInstance, type FastifyRequest } from "fastify";
import cors from "@fastify/cors";
import { isIP } from "node:net";
import { parseSpec } from "../../assessment-engine/src/index.js";
import { withTenant, uuid } from "../../database/src/index.js";
import { validatePlan } from "../../contracts/src/policy.js";

type TargetInput = { name: string; baseUrl: string; environment: string };
type UploadInput = { filename: string; content: string };
class ApiError extends Error { constructor(public statusCode: number, public code: string) { super(code); } }
const sessions = new WeakMap<FastifyRequest,string>();
const idPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
function tenant(req: FastifyRequest) { const value = sessions.get(req); if (!value) throw new ApiError(401,"UNAUTHORIZED"); return value; }
function validId(value: unknown): string { if (typeof value !== "string" || !idPattern.test(value)) throw new ApiError(400,"INVALID_ID"); return value; }
function paramsId(req: FastifyRequest) { return validId((req.params as {id?:string}).id); }
function bodyObject(value: unknown): Record<string,unknown> {
  if (!value || Array.isArray(value) || typeof value !== "object") throw new ApiError(400,"INVALID_BODY");
  return value as Record<string,unknown>;
}
function validUrl(value: unknown): string {
  if (typeof value !== "string" || value.length > 2048) throw new ApiError(400,"INVALID_TARGET_URL");
  let url: URL;
  try { url = new URL(value); } catch { throw new ApiError(400,"INVALID_TARGET_URL"); }
  const host = url.hostname.toLowerCase().replace(/\.$/,"");
  if (url.protocol !== "https:" || url.username || url.password || url.hash || url.search ||
      isIP(host) !== 0 || !host.includes(".") || /(^|\.)(localhost|local|internal|test)$/.test(host) ||
      /(^|\.)(localhost|local|internal)$/.test(host) || url.port && url.port !== "443")
    throw new ApiError(400,"UNSAFE_TARGET_URL");
  return url.origin + url.pathname.replace(/\/$/,"");
}
function positiveLimit(req: FastifyRequest) {
  const obj = req.query as Record<string,unknown>;
  const n = obj.limit === undefined ? 50 : Number(obj.limit);
  const offset = obj.offset === undefined ? 0 : Number(obj.offset);
  if (!Number.isInteger(n) || n < 1 || n > 100 || !Number.isSafeInteger(offset) || offset < 0 || offset > 1000000) throw new ApiError(400,"INVALID_PAGINATION");
  return { limit:n, offset };
}
function setupSyntheticAuthority(): Map<string,string> {
  if (process.env.NODE_ENV === "production" || process.env.SYNTHETIC_AUTH_ENABLED !== "true") throw new Error("HOST_AUTHORITY_NOT_CONFIGURED_PRODUCTION_FAIL_CLOSED");
  let input: unknown;
  try { input = JSON.parse(process.env.DEV_TOKENS_JSON ?? "{}"); } catch { throw new Error("INVALID_SYNTHETIC_AUTH_CONFIGURATION"); }
  if (!input || typeof input !== "object" || Array.isArray(input) || Object.keys(input).length === 0) throw new Error("SYNTHETIC_AUTH_MUST_BE_EXPLICIT");
  const tokens = new Map<string,string>();
  for (const [token, id] of Object.entries(input)) {
    if (token.length < 12 || !idPattern.test(String(id))) throw new Error("INVALID_SYNTHETIC_AUTH_MAPPING");
    tokens.set(token,String(id));
  }
  return tokens;
}
export async function makeApp(): Promise<FastifyInstance> {
  const identities = setupSyntheticAuthority();
  const app = Fastify({ logger: false, bodyLimit: 1100000, genReqId: () => uuid() });
  await app.register(cors, { origin:["http://127.0.0.1:5173","http://localhost:5173"], allowedHeaders: ["authorization","content-type","idempotency-key"], methods: ["GET","POST","DELETE","OPTIONS"] });
  app.addHook("preHandler", async (req) => {
    if (req.url === "/health/live") return;
    const authorization = req.headers.authorization;
    if (!authorization?.startsWith("Bearer ")) throw new ApiError(401,"UNAUTHORIZED");
    const id = identities.get(authorization.slice(7));
    if (!id) throw new ApiError(403,"PERMISSION_DENIED");
    sessions.set(req,id);
  });
  app.setErrorHandler((error,req,reply) => {
    const e = error as Error & { statusCode?:number; code?:string };
    const status = e instanceof ApiError ? e.statusCode : e.statusCode === 413 ? 413 : e.code === "23505" ? 409 : 500;
    req.log.error({requestId:req.id,code:status},"request failed");
    reply.code(status).send({ error: e instanceof ApiError ? e.code : status === 413 ? "BODY_TOO_LARGE" : status === 409 ? "CONFLICT" : "INTERNAL_ERROR", requestId:req.id });
  });
  app.get("/health/live",async()=> ({ok:true,service:"api-family",scope:"SPEC_ONLY"}));
  app.post("/v1/targets", async (req, reply) => {
    const data = bodyObject(req.body), name=data.name, environment=data.environment;
    if (typeof name !== "string" || name.trim().length < 1 || name.length > 120 || !["SYNTHETIC","STAGING","PRODUCTION"].includes(String(environment))) throw new ApiError(400,"INVALID_TARGET");
    const url=validUrl(data.baseUrl), id=uuid(), t=tenant(req);
    const record=await withTenant(t,async tx=>{
      const r=await tx.query("INSERT INTO api_targets(id,tenant_id,name,base_url,environment) VALUES($1,$2,$3,$4,$5) RETURNING id,name,base_url,environment,created_at",[id,t,name.trim(),url,environment]);
      await tx.query("INSERT INTO api_audit(id,tenant_id,action,subject_id) VALUES($1,$2,'TARGET_CREATED',$3)",[uuid(),t,id]);
      return r.rows[0];
    });
    reply.code(201).send(record);
  });
  app.get("/v1/targets",async req => {
    const p=positiveLimit(req);
    return withTenant(tenant(req), async tx => (await tx.query("SELECT id,name,base_url,environment,created_at FROM api_targets ORDER BY created_at,id LIMIT $1 OFFSET $2",[p.limit,p.offset])).rows);
  });
  app.get("/v1/targets/:id",async req => {
    const r=await withTenant(tenant(req),async tx=>tx.query("SELECT id,name,base_url,environment,created_at FROM api_targets WHERE id=$1",[paramsId(req)]));
    if (!r.rows[0]) throw new ApiError(404,"NOT_FOUND");
    return r.rows[0];
  });
  app.post("/v1/targets/:id/specifications", async (req,reply) => {
    const id=paramsId(req), data=bodyObject(req.body);
    const filename=data.filename, content=data.content;
    if (typeof filename !== "string" || !/^[a-zA-Z0-9_.-]{1,120}\.(json|ya?ml)$/i.test(filename) || typeof content !== "string") throw new ApiError(400,"INVALID_SPEC_UPLOAD");
    let spec;
    try { spec=parseSpec(content); } catch (e) { throw new ApiError(422,"INVALID_SPEC_" + String(e instanceof Error ? e.message : "DOCUMENT").slice(0,60).replace(/[^A-Z0-9_]/gi,"_")); }
    const t=tenant(req), specId=uuid();
    await withTenant(t,async tx=>{
      const target=await tx.query("SELECT id FROM api_targets WHERE id=$1",[id]);
      if (!target.rows[0]) throw new ApiError(404,"TARGET_NOT_FOUND");
      await tx.query("INSERT INTO api_specifications(id,tenant_id,target_id,filename,format,fingerprint,raw_spec) VALUES($1,$2,$3,$4,$5,$6,$7)",[specId,t,id,filename,spec.format,spec.fingerprint,content]);
      for (const op of spec.operations) await tx.query("INSERT INTO api_operations(id,tenant_id,specification_id,operation_key,method,path,operation_id,pointer,security_json) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb)",[uuid(),t,specId,op.key,op.method,op.path,op.operationId,op.pointer,JSON.stringify(op.security)]);
      await tx.query("INSERT INTO api_audit(id,tenant_id,action,subject_id) VALUES($1,$2,'SPEC_UPLOADED',$3)",[uuid(),t,specId]);
    });
    reply.code(201).send({id:specId,targetId:id,fingerprint:spec.fingerprint,format:spec.format,operationCount:spec.operations.length,warnings:spec.warnings});
  });
  app.get("/v1/targets/:id/specifications",async req => {
    const p=positiveLimit(req);
    return withTenant(tenant(req),async tx=>(await tx.query("SELECT id,filename,format,fingerprint,created_at FROM api_specifications WHERE target_id=$1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",[paramsId(req),p.limit,p.offset])).rows);
  });
  app.get("/v1/specifications/:id/operations",async req=>{
    const p=positiveLimit(req);
    return withTenant(tenant(req),async tx=>(await tx.query("SELECT operation_key AS key,method,path,operation_id AS \"operationId\",pointer,security_json AS security FROM api_operations WHERE specification_id=$1 ORDER BY operation_key LIMIT $2 OFFSET $3",[paramsId(req),p.limit,p.offset])).rows);
  });
  app.post("/v1/targets/:id/assessments", async (req,reply)=>{
    const targetId=paramsId(req), data=bodyObject(req.body);
    const specId=validId(data.specificationId);
    try { validatePlan({mode:data.mode,methods:[],maxRequests:1}); } catch { throw new ApiError(400,"ONLY_SPEC_ONLY_SUPPORTED"); }
    const key=req.headers["idempotency-key"];
    if (typeof key !== "string" || !/^[a-zA-Z0-9:_-]{8,128}$/.test(key)) throw new ApiError(400,"IDEMPOTENCY_KEY_REQUIRED");
    const t=tenant(req), id=uuid();
    const result=await withTenant(t,async tx=>{
      const exists=await tx.query("SELECT id FROM api_specifications WHERE id=$1 AND target_id=$2",[specId,targetId]);
      if (!exists.rows[0]) throw new ApiError(404,"SPECIFICATION_NOT_FOUND");
      const r=await tx.query("INSERT INTO api_assessments(id,tenant_id,target_id,specification_id,status,mode,idempotency_key) VALUES($1,$2,$3,$4,'QUEUED','SPEC_ONLY',$5) ON CONFLICT(tenant_id,idempotency_key) DO UPDATE SET id=api_assessments.id RETURNING id,target_id,specification_id,status,mode,created_at",[id,t,targetId,specId,key]);
      if (r.rows[0].specification_id !== specId || r.rows[0].target_id !== targetId) throw new ApiError(409,"IDEMPOTENCY_CONFLICT");
      if (r.rows[0].status === "QUEUED") await tx.query("INSERT INTO api_assessment_queue(assessment_id,tenant_id) VALUES($1,$2) ON CONFLICT DO NOTHING",[r.rows[0].id,t]);
      return r.rows[0];
    });
    reply.code(result.id===id?201:200).send(result);
  });
  app.get("/v1/assessments/:id", async req=>{
    const r=await withTenant(tenant(req),async tx=>tx.query("SELECT id,target_id AS \"targetId\",specification_id AS \"specificationId\",mode,status,error_code AS \"errorCode\",created_at,completed_at FROM api_assessments WHERE id=$1",[paramsId(req)]));
    if (!r.rows[0]) throw new ApiError(404,"NOT_FOUND");
    return r.rows[0];
  });
  app.get("/v1/assessments/:id/findings",async req=>{
    const p=positiveLimit(req);
    return withTenant(tenant(req),async tx=>(await tx.query("SELECT f.id,f.rule_id AS \"ruleId\",f.operation_key AS \"operationKey\",f.category,f.explanation,f.remediation,f.confidence,f.validation_level AS \"validationLevel\",f.review_required AS \"reviewRequired\",e.id AS \"evidenceId\",e.content_json AS evidence FROM api_findings f JOIN api_evidence e ON e.id=f.evidence_id AND e.tenant_id=f.tenant_id WHERE f.assessment_id=$1 ORDER BY f.rule_id,f.operation_key LIMIT $2 OFFSET $3",[paramsId(req),p.limit,p.offset])).rows);
  });
  app.get("/v1/assessments/:id/report",async req=>{
    const id=paramsId(req);
    return withTenant(tenant(req),async tx=>{
      const r=await tx.query("SELECT projection FROM api_reports WHERE assessment_id=$1",[id]);
      if (!r.rows[0]) throw new ApiError(404,"REPORT_NOT_READY_OR_NOT_FOUND");
      return r.rows[0].projection;
    });
  });
  app.post("/v1/assessments/:id/cancel",async req=>{
    const id=paramsId(req);
    return withTenant(tenant(req),async tx=>{
      await tx.query("SELECT assessment_id FROM api_assessment_queue WHERE assessment_id=$1 FOR UPDATE",[id]);
      const r=await tx.query("UPDATE api_assessments SET status='CANCELLED',completed_at=now() WHERE id=$1 AND status IN ('QUEUED','PROCESSING') RETURNING id,status",[id]);
      if (!r.rows[0]) throw new ApiError(409,"NOT_CANCELLABLE_OR_NOT_FOUND");
      await tx.query("DELETE FROM api_assessment_queue WHERE assessment_id=$1",[id]);
      await tx.query("INSERT INTO api_audit(id,tenant_id,action,subject_id) VALUES($1,$2,'ASSESSMENT_CANCELLED',$3)",[uuid(),tenant(req),id]);
      return r.rows[0];
    });
  });
  return app;
}
